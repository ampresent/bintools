from pydbg import *
from pydbg.defines import *
import pefile
import sys
import struct
import argparse
import pickle
import os

class sandbox():
	def __init__(self, target, options):
	# Only for use of disable API, to speed up
		# For general use, containing time to live etc.
		self.handlers = dict()
		# Instruction stream
		self.inst_stream = []
		# Modules chosen to be visible when tracing
		# Maybe useless when coloring IDA pro
		self.visible_modules = []
		self.visible_modules.append(os.path.basename(target))
		self.module_sections = []
		# If any trace specified
		trace_option = filter(lambda x:x.utils=='trace', options)
		if (trace_option):
			self.visible_module = reduce(list.__iadd__, [x.module for x in trace_option])
		self.trace = True
		# Pydbg object
		self.dbg = pydbg()
		self.dbg.load(target)
		self.pe = pefile.PE(target)
		# Raw option
		self.options = options
		# The reason I use -s for MITM, is MITM will not only be used on APIs. Use it for disabling too, for convience
		for opt in self.options:
			if opt.utils in ['disable', 'mitm'] and not opt.search:
				if opt.utils=='disable':
					handler = self.__ban_handle
				elif opt.utils=='mitm':
					handler = self.__modify_param_handle
				# Dealing handlers with the same option
				for bp in opt.breakpoint:
					self.handlers[bp] = copy.deepcopy(opt)
					self.handlers[bp].breakpoint = bp
					self.handlers[bp].name = 'Undefined'
					if opt.type == 'hardware':
						self.dbg.bp_set_hw(bp, 1, HW_EXECUTE, handler=handler)
					else:
						self.dbg.bp_set(bp, handler=handler)
		self.oep = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		self.dbg.bp_set(self.oep, restore=False, handler=self.__oep_handle)

	# Run the debugger
	def run(self):
		self.dbg.run()

	# Works with self.handlers
	def __ban_handle(self, dbg):
		func_addr = dbg.context.Eip
		func_name = self.handlers[func_addr].name
		print '[+] Banning API: %s\t0x%x' % (func_name, func_addr)
		det = 1
		# There should be range detection???
		while True:
			ins = dbg.disasm_around(func_addr, det)[-1]
			if ins[1].startswith('retn'):
				# jump to retn n, what if there's no retn? there's the chance
				dbg.set_register('EIP', ins[0])
				break
			det += 1

		self.__handler_count_down(func_addr)
		return DBG_CONTINUE

	def __gpa_ret_handle(self, dbg):
		func_addr = dbg.context.Eax
		func_name = self.last_dyn_API

		for opt in self.options:
			if opt.search and func_name in opt.breakpoint:
				if opt.utils == 'disable':
					handler = self.__ban_handle
				elif opt.utils == 'mitm':
					handler = self.__modify_param_handle

				if opt.type == 'hardware':
					dbg.bp_set_hw(func_addr, 1, HW_EXECUTE, handler=handler)
				else:
					dbg.bp_set(func_addr, handler=handler)
				self.handlers[func_addr] = copy.deepcopy(opt)
				self.handlers[func_addr].breakpoint = func_addr
				self.handlers[func_addr].name = func_name

		return DBG_CONTINUE

	# Not of much use, only to retrieve func_name, and set breakpoint on retn
	def __gpa_handle(self, dbg):
		#print '[*] Breaking on GetProcAddress: 0x%x' % dbg.context.Eip
		# 32 elf system only
		esp = dbg.context.Esp
		ret = struct.unpack('<I', dbg.read(esp, 4))[0]

		func_name_ptr = struct.unpack('<I', dbg.read(esp+8, 4))[0]
		try:
			# Should check the range
			func_name = dbg.read(func_name_ptr, 50)
		except:
			# Strange, a lot of failed ones
			#print '[-] Parsing function at 0x%x failed, ignore' % func_name_ptr
			return DBG_CONTINUE
		func_name = dbg.get_ascii_string(func_name)
		# Func_addr unknown yet until GetProcAddress returns

		#print '[+] Forbidden API detected: %s' % func_name

		# Execute Until Return
		dbg.bp_set(ret, restore=False, handler=self.__gpa_ret_handle)
		self.last_dyn_API = func_name
		return DBG_CONTINUE

	# STILL FAULTY COMPLETELY
	'''
	def ll_handle(dbg):
		esp = dbg.context.Esp
		module_name_ptr = dbg.read(esp+4, 4)
		ret = dbg.read(esp, 4)
		ret = struct.unpack('<I', ret)[0]
		module_name_ptr = struct.unpack('<I', module_name_ptr)[0]
		module_name = dbg.read(module_name_ptr, 50)
		module_name = dbg.get_ascii_string(module_name)
		if module_name == 'chopper_Plugin.dll':
			#dbg.bp_set_hw(0x10001363, restore=False, handler=xxx_handle)
			dbg.bp_set(ret, restore=False, handler=ll_ret_handle)
		return DBG_CONTINUE

	def ll_ret_handle(dbg):
		xxx = dbg.context.Eax
		print xxx
		rva = 363
		#dbg.bp_set_hw(xxx + rva, 4, HW_EXECUTE, restore=False, handler=xxx_handle)
		return DBG_CONTINUE
	'''

	# Works with self.handlers
	def __handler_count_down(self, eip):
		if self.handlers[eip].time > -1:
			self.handlers[eip].time -= 1
		print '[*] Handler %s\t0x%x expired' % (self.handlers[eip].name, eip)
		if self.handlers[eip].time == 0:
			if self.handlers[eip].type == 'hardware':
				self.dbg.bp_del_hw(eip)
			else:
				self.dbg.bp_del(eip)

	# Works with self.handlers
	def __modify_param_handle(self, dbg):
		eip = dbg.context.Eip
		esp = dbg.context.Esp
		addr = esp + self.handlers[eip].offset
		into = self.handlers[eip].into
		display = self.handlers[eip].display
		if self.handlers[eip].indirect:
			param = dbg.read(addr, 4)
			param = struct.unpack('<I', param)[0]
			addr = param
		if display == '%s':
			length = self.handlers[eip].length
			param = dbg.read(addr, length)
			param = dbg.get_ascii_string(param)
			print '[+] Param on the stack: %s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into %s' % into
			dbg.write(addr, into, length)
		elif display == '%d':
			param = dbg.read(addr, 4)
			param = struct.unpack('<I', param)[0]
			print '[+] Param on the stack: %d' % param
			print '[+] \tChanged into: %d' % into
			into = struct.pack('<I', int(into))
			dbg.write(addr, into, 4)
		elif display == '%l':
			param = dbg.read(addr, 8)
			param = struct.unpack('<L', param)[0]
			print '[+] Param on the stack: %l' % param
			print '[+] \tChanged into %l' % into
			into = struct.pack('<L', long(into))
			dbg.write(addr, into, 8)
		elif display == '%x':
			param = dbg.read(addr, 4)
			param = struct.unpack('<I', param)[0]
			print '[+] Param on the stack: 0x%x' % param
			print '[+] \tChanged into: 0x%x' % into
			into = struct.pack('<I', int(into))
			dbg.write(addr, into, 4)
		self.__handler_count_down(eip)
		return DBG_CONTINUE

	def __oep_handle(self, dbg):
		print '[*] Breaking on OEP: 0x%x' % dbg.context.Eip
		# Enumerate modules loaded for now
		# MAYBE I NEED TO WATCH LOAD_LIBRARY FUNCTION NOW!!!!!
		for module in dbg.iterate_modules():
			if module.szModule in self.visible_modules:
				self.module_sections.append((module.modBaseAddr, module.modBaseAddr+module.modBaseSize))
		# Set singlestep breakpoint for trace utility
		if self.trace:
			dbg.set_callback(EXCEPTION_SINGLE_STEP, self.__trace_handle)
			for thread_id in dbg.enumerate_threads():
				print '[+] Single step for thread %d' % thread_id
				# What's the thread used for?
				h_thread = dbg.open_thread(thread_id)
				dbg.single_step(True, thread_handle=h_thread)
				dbg.close_handle(h_thread)
			dbg.resume_all_threads()

		# TWO functions:	1. Detecting forbidden API.
		#					2. Search for API by name
		# POSSIBLY LOAD_TIME LINKING SHOULD NOT BE PUT IN THE OEP HANDLE
		# Load-time Dynamic Linking
		self.__dyn_link(self.pe, self.dbg)
		# Run-time Dynamic Linking
		getprocaddr = self.dbg.func_resolve('kernel32.dll', 'GetProcAddress')
		dbg.bp_set(getprocaddr, handler=self.__gpa_handle)
		self.handlers[getprocaddr] = argparse.Namespace()
		self.handlers[getprocaddr].breakpoint = getprocaddr
		self.handlers[getprocaddr].name = 'GetProcAddress'

		# NO USE FOR NOW
		#loadlibrary = dbg.func_resolve('kernel32.dll', 'LoadLibraryA')
		#dbg.bp_set(loadlibrary, handler=ll_handle)
		return DBG_CONTINUE

	def __trace_handle(self, dbg):
		eip = dbg.context.Eip
		self.inst_stream.append(eip)
		# If eip is within visible modules, then break at it
		if filter(lambda x: x[0]<=eip<=x[1], self.module_sections):
			dbg.single_step(True)
		# Else, break at return address
		else:
			esp = dbg.context.Esp
			ret = dbg.read(esp, 4)
			ret = struct.unpack("<I", ret)[0]
			dbg.bp_set(ret, restore=False, handler=self.__trace_handle)
			dbg.single_step(False)
		return DBG_CONTINUE

	def __dyn_link(self, pe, dbg):
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in entry.imports:
				func_name = imp.name
				func_addr = dbg.read(imp.address, 4)
				func_addr = struct.unpack('<I', func_addr)[0]

				for opt in self.options:
					if opt.utils in ['disable', 'mitm'] and opt.search and func_name in opt.breakpoint:
						print '[+] Forbidden API detected: %s\t0x%x' % (func_name, func_addr)
						if opt.utils == 'disable':
							handler = self.__ban_handle
						elif opt.utils == 'mitm':
							handler = self.__modify_param_handle

						if opt.type == 'hardware':
							dbg.bp_set_hw(func_addr, 1, HW_EXECUTE, handler=handler)
						else:
							dbg.bp_set(func_addr, handler=handler)
						self.handlers[func_addr] = copy.deepcopy(opt)
						self.handlers[func_addr].breakpoint = func_addr
						self.handlers[func_addr].name = func_name

def parse_options(args):
	parser = argparse.ArgumentParser()
	subparses = parser.add_subparsers(title='Utils', dest='utils', help='USE %(prog)s disable -h OR %(prog)s mitm -h FOR DETAILS')
	parser_disable = subparses.add_parser('disable', help='Disable specified APIs.')
	parser_disable.add_argument('-i', '--interactive', action='store_true', dest='interactive', default=False, help='Prompt before disabling')
	parser_disable.add_argument('-b', action='store', dest='breakpoint', required=True, help='Breakpoint. Name or address, depending on -s', nargs='+')
	parser_disable.add_argument('-t', action='store', choices=['hardware', 'memory'], dest='type', default='memory', help='Type of breakpoint. Memory by default')
	parser_disable.add_argument('--no-search', action='store_false', dest='search', default=True, help='Don\'t search for the name, given by -b. Search by default')
	parser_disable.add_argument('--time', action='store', type=int, dest='time', default='-1', help='Time to live for the handler')
	parser_mitm = subparses.add_parser('mitm', help='Man in the Middle')
	parser_mitm.add_argument('--indirect', action='store_true', dest='indirect', default=False, help='Indirect Address. False by default')
	parser_mitm.add_argument('--offset', action='store', type=int, dest='offset', required=True, help='Bytes offset to the param from esp')
	parser_mitm.add_argument('--length', action='store', type=int, dest='length', help='The length of the continuous memory')
	parser_mitm.add_argument('--into', dest='into', required=True, help='Change bytes into')
	parser_mitm.add_argument('--display', action='store', choices=['%s', '%d', '%l', '%x'],
								default='%s', dest='display', help='Format of displaying')
	parser_mitm.add_argument('-b', action='store', dest='breakpoint', required=True, help='Breakpoint. Name or address, depending on -s', nargs='+')
	parser_mitm.add_argument('-t', action='store', choices=['hardware', 'memory'], dest='type', default='memory', help='Type of breakpoint. Memory by default')
	parser_mitm.add_argument('--no-search', action='store_false', dest='search', default=True, help='Don\'t search for the name, given by -b. Search by default')
	parser_mitm.add_argument('--time', action='store', type=int, dest='time', default='-1', help='Time to live for the handler')
	parser_trace = subparses.add_parser('trace', help='Trace the execution of instructions.')
	parser_trace.add_argument('-f', action='store', dest='file', help='Output File')
	parser_trace.add_argument('-m', action='append', dest='module', help='Visible Modules')
	parser.add_argument('-l', action='store', dest='log', help='Log filename. Not supported yet.')
	parser.add_argument('-c', action='store', dest='crash-report', help='Crash report filename. Not supported yet.')

	option = parser.parse_args(args)

	# MITM argument check
	if option.utils == 'mitm':
		if  option.display == '%s' and len(option.into)!=option.length:
			sys.stderr.write('[-] Length is incompatible with into')
			exit(0)
		try:
			if option.display == '%d':
				option.into = int(option.into)
			elif option.display == '%l':
				option.into = long(option.into)
			elif option.display == '%x':
				option.into = int(option.into[2:], 16)
		except:
			sys.stderr.write('[-] Wrong input format')
			exit(0)

	# Translate breakpoint into integer
	if option.utils in ['mitm', 'disable'] and not option.search:
		for i, bp in enumerate(option.breakpoint):
			if bp.startswith('0x'):
				option.breakpoint[i] = int(bp[2:], 16)
			else:
				option.breakpoint[i] = int(bp)
	return option

if __name__ == '__main__':
	# WTF, sys.argv[0]:win32_sandbox.py???
	options = parse_options(sys.argv[2:])
	a = sandbox(sys.argv[1], [options])
	a.run()

	if options.file:
		with open(options.file, 'w+') as f:
			pickle.dump(a.inst_stream, f)
	print '[*] Exit'
