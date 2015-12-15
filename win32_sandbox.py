from pydbg import *
from pydbg.defines import *
import pefile
import sys
import struct
import argparse
import copy
import os
import json
import hexsed
import itertools
import operator

class sandbox():
	def __init__(self):
		self.breakpoints = []
		self.handlers = []
		self.global_handlers = []
		self.dbg = pydbg()
		self.dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT, self.__create_process_handle)
		self.dbg.set_callback(EXCEPTION_SINGLE_STEP, self.__universal_handle)
		self.plugins = {
			'disable': {'handler': self.__disable_handle},
			'trace': {'pre_process': self.__trace_pre_process, 'handler': self.__trace_start_handle, 'post_process': self.__trace_post_process},
			'mitm':{'handler': self.__mitm_handle},
			'intercept':{'handler':self.__intercept_handler}
		}

	# Run the debugger
	def run(self):
		self.dbg.run()

	# Works with self.handlers
	def __disable_handle(self, dbg, handler):
		func_addr = dbg.context.Eip
		func_name = self.breakpoints[handler['bp']]['name']
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

		return DBG_CONTINUE

	def __gpa_ret_handle(self, dbg):
		func_addr = dbg.context.Eax
		func_name = self.last_dyn_API

		for i, bp in enumerate(self.breakpoints):
			if bp['search'] and not bp['resolved']:
				module, func = bp['addr'].split('@')
				# I SHOULD DEAL WITH module!!!!!!!
				module = module.lower()
				if func == func_name:
					bp['addr'] = func_addr
					bp['name'] = func_name
					print '[+] Place breakpoint on %s:0x%x' % (func_name,func_addr)
					if bp['type'] == 'hardware':
						dbg.bp_set_hw(func_addr, 1, HW_EXECUTE, handler=self.__universal_handle)
					else:
						dbg.bp_set(func_addr, handler=self.__universal_handle)

		return DBG_CONTINUE

	# Not of much use, only to retrieve func_name, and set breakpoint on retn
	def __gpa_handle(self, dbg):
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
	def __handler_count_down(self, bp):
		if bp['time'] > 0:
			bp['time'] -= 1
			if bp['time'] == 0:
				print '[*] Handler expired at: %s\t0x%x' % (bp['name'], bp['addr'])
				if bp['time'] == 'hardware':
					self.dbg.bp_del_hw(bp['addr'])
				else:
					self.dbg.bp_del(bp['addr'])

	# Works with self.handlers
	def __mitm_handle(self, dbg):
		eip = dbg.context.Eip
		if self.handlers[eip].offset:
			esp = dbg.context.Esp
			addr = esp + self.handlers[eip].offset
		elif self.handlers[eip].address:
			addr = self.handlers[eip].address
		# If indirect specified , lookup addres
		if self.handlers[eip].indirect:
			param = dbg.read(addr, 4)
			param = struct.unpack('<I', param)[0]
			addr = param

		display = self.handlers[eip].display
		if display == '%s':
			into = self.handlers[eip].into
			length = len(into)
			param = dbg.read(addr, length)
			param = dbg.get_ascii_string(param)
			print '[+] Param on the stack: %s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into %s' % (into[0:20]+'...' if length > 20 else into)
			dbg.write(addr, into, length)
		elif display == '%d':
			splited = self.handlers[eip].into.split()
			n = len(splited)
			into = hexsed.reformat('d', 'w', splited)
			length = len(into)
			into = ''.join(into)
			param = dbg.read(addr, length)
			param = ', '.join(struct.unpack('<'+'I'*n, param))
			print '[+] Param on the stack: %s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into: %s' % self.handlers[eip].into
			dbg.write(addr, into, length)
		elif display == '%l':
			splited = self.handlers[eip].into.split()
			n = len(splited)
			into = hexsed.reformat('d', 'g', splited)
			length = len(into)
			into = ''.join(into)
			param = dbg.read(addr, length)
			param = ', '.join(map(str, struct.unpack('<'+'L'*n, param)))
			print '[+] Param on the stack: %s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into %s' % (self.handlers[eip].into[0:20]+'...' if length>20 else self.handlers[eip].into)
			dbg.write(addr, into, length)
		elif display == '%x':
			splited = self.handlers[eip].into.split()
			n = len(splited)
			into = hexsed.reformat('x', 'w', splited)
			length = len(into)
			into = ''.join(into)
			param = dbg.read(addr, length)
			param = ', 0x'.join(map(str, map(hex, struct.unpack('<'+'I'*n, param))))
			print '[+] Param on the stack: 0x%s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into: %s' % (self.handlers[eip].into[0:20]+'...' if length>20 else self.handlers[eip].into)
			dbg.write(addr, into, length)
		elif display == '%b':
			splited = self.handlers[eip].into.split()
			n = len(splited)
			into = hexsed.reformat('x', 'b', splited)
			length = len(into)
			into = ''.join(into)
			param = dbg.read(addr, length)
			param = ', '.join(map(str, map(hex, struct.unpack('<'+'B'*n, param))))
			print '[+] Param on the stack: 0x%s' % (param[0:20]+'...' if length > 20 else param)
			print '[+] \tChanged into: %s' % (self.handlers[eip].into[0:20]+'...' if length>20 else self.handlers[eip].into)
			dbg.write(addr, into, length)
		self.__handler_count_down(eip)
		return DBG_CONTINUE

	def __create_process_handle(self, dbg):
		self.base_of_image = dbg.dbg.u.CreateProcessInfo.lpBaseOfImage
		# Only one option should contain oep, or only root option should contain oep, how to guarantee???????????
		if not self.options['oep']:
			self.options['oep'] = self.oep_rva + self.base_of_image
		else:
			self.options['oep'] = self.options['oep']-self.fake_base_of_image+self.base_of_image
		dbg.bp_set(self.options['oep'], restore=False, handler=self.__oep_handle)

		for hs in self.handlers.itervalues():
			for h in hs:
				if 'pre_process' in self.plugins[h['util']]:
					self.plugins[h['util']]['pre_process'](h)
		return DBG_CONTINUE

	def __oep_handle(self, dbg):
		print '[*] Breaking on OEP: 0x%x' % dbg.context.Eip
		# Enumerate modules loaded for now
		# Load-time Dynamic Linking
		self.__dyn_link()
		# Run-time Dynamic Linking
		dbg.bp_set(dbg.func_resolve_debuggee('kernel32.dll', 'GetProcAddress'), handler=self.__gpa_handle)

		self.__universal_handle(dbg)
		#I'll NEED IT ! BECAUSE IF GetProcAddress CALLED WITHOUD UPDATING loaded_modules, IT"S NO USE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		#loadlibrary = dbg.func_resolve('kernel32.dll', 'LoadLibraryA')
		#dbg.bp_set(loadlibrary, handler=ll_handle)

		return DBG_CONTINUE

	def __trace_pre_process(self, h):
		if 'file' in h:
			h['fd'] = open(h['file'], 'w')
		else:
			h['fd'] = sys.stdout
			h['file'] = 'Stdout'
		if 'colide' in h:
			h['colide'].setdefault('coverage_ratio_thredshold', 1.0001)
			if 'file' not in h['colide']:
				raise
			h['colide']['file'] = open(h['colide']['file'])
		h.setdefault('visible_modules', [])
		h['visible_modules'].append(os.path.basename(self.options['target']).lower())
		h['inst_stream'] = []
		h['relay'] = False

	def __trace_post_process(self, h):
		h['fd'].write('\n'.join(['0x%x'%i for i in h['inst_stream']]))
		print '[+] Tracing file dumped: %s' % h['file']
		h['fd'].close()

		if 'colide' in h:
			h['colide']['file'].close()

	def __trace_start_handle(self, dbg, handler):
		eip = dbg.context.Eip
		if not handler['relay']:
			print '[+] Start tracing at: 0x%x' % eip
		within = filter(lambda x: x['start']<=eip<=x['end'], map(lambda y:self.loaded_modules[y], handler['visible_modules']))
		if within:
			handler['inst_stream'].append(eip-within[0]['start']+within[0]['fake_start'])
		for thread_id in dbg.enumerate_threads():
			# What's the thread used for?
			h_thread = dbg.open_thread(thread_id)
			dbg.single_step(True, thread_handle=h_thread)
			dbg.close_handle(h_thread)
		self.global_handlers.append({'handle':self.__trace_handle, 'orig_handler':handler})
		dbg.resume_all_threads()
		return DBG_CONTINUE

	def __intercept_handler(self, dbg, handler):
		pass

	def __trace_handle(self, dbg, tmp_handler):
		eip = dbg.context.Eip
		handler = tmp_handler['orig_handler']
		# If eip is within visible modules, then break at it
		within = filter(lambda x: x['start']<=eip<=x['end'], map(lambda y:self.loaded_modules[y],handler['visible_modules']))
		if within:
			handler['inst_stream'].append(eip-within[0]['start']+within[0]['fake_start'])
			dbg.single_step(True)
		# Else, break at return address
		else:
			esp = dbg.context.Esp
			ret = dbg.read(esp, 4)
			ret = struct.unpack("<I", ret)[0]

			# WILL I MISS SOMETHING THAT STARTS IN OTHER MODULE AND END UP IN VISIBLE ONES
			if filter(lambda x: x['start']<=ret<=x['end'], map(lambda y:self.loaded_modules[y], handler['visible_modules'])):
				# Reuse the handler
				# Trace should never share a breakpoint with others
				dbg.bp_del(self.breakpoints[handler['bp']]['addr'])
				dbg.bp_set(ret, restore=False, handler=self.__universal_handle)
				self.breakpoints[handler['bp']]['addr'] = ret
				handler['relay'] = True
				self.global_handlers.remove(tmp_handler)
				dbg.single_step(False)
		return DBG_CONTINUE

	def __getImageBase(self, fname):
		with open(fname) as f:
			f.seek(0x3c)
			nt_header=struct.unpack('<I',f.read(4))[0]
			f.seek(nt_header + 0x34)
			imagebase=struct.unpack('<I',f.read(4))[0]
			return imagebase

	def __dyn_link(self):
		self.loaded_modules = {}

		for module in self.dbg.iterate_modules():
			self.loaded_modules[module.szModule.lower()] = {
					'start'		:module.modBaseAddr,
					'end'		:module.modBaseAddr+module.modBaseSize,
					'fake_start':self.__getImageBase(module.szExePath)
					}
		for i, bp in enumerate(self.breakpoints):
			bp['resolved'] = True
			if bp['search']:
				module, func = bp['addr'].split('@')
				module = module.lower()
				if module in self.loaded_modules:
					bp['addr'] = self.dbg.func_resolve_debuggee(module, func)
					bp['name'] = func
					print '[+] Place breakpoint at %s\t0x%x' % (func, bp['addr'])
				else:
					bp['resolved'] = False
					continue
			elif bp['addr'] == '@oep': 
				bp['addr'] = self.options['oep']
				bp['name'] = 'OEP'
				print '[+] Place breakpoint at %s\t0x%x' % ('oep',bp['addr'])
			else:
				print '[+] Place breakpoint at\t0x%x' % bp['addr']

			if not bp['search'] or bp['resolved']:
				try:
					if bp['type'] == 'hardware':
						self.dbg.bp_set_hw(bp['addr'], 1, HW_EXECUTE, handler=self.__universal_handle)
					else:
						self.dbg.bp_set(bp['addr'], handler=self.__universal_handle)
				except:
					print '[-] Failed to place breakpoint\t0x%x' % bp['addr']

	def __universal_handle(self, dbg):
		eip = dbg.context.Eip
		for h in self.global_handlers:
			h['handle'](dbg, h)
		for bp in filter(lambda x:x['addr']==eip and x['time']!=0, self.breakpoints):
			handlers = self.handlers[bp['id']] 
			for h in handlers:
				if 'pre_action' in h:
					self.actions[h['pre_action']](dbg)
			for h in handlers:
				self.plugins[h['util']]['handler'](dbg, h)
			for h in handlers:
				if 'post_action' in h:
					self.actions[h['post_action']](dbg)
			self.__handler_count_down(bp)
		return DBG_CONTINUE

	def post_process(self):
		for hs in self.handlers.itervalues():
			for h in hs:
				if 'pre_process' in self.plugins[h['util']]:
					self.plugins[h['util']]['post_process'](h)

	def load_project(self, fname):
		with open(fname) as f:
			self.options = json.load(f)
		self.breakpoints = self.options['breakpoints']
		for i, bp in enumerate(self.breakpoints):
			if 'addr' not in bp:
				raise
			bp.setdefault('search', False)
			bp.setdefault('name', '')
			bp.setdefault('action', '')
			bp.setdefault('time', -1)
			bp.setdefault('ignore', 0)
			bp.setdefault('type', 'memory')
			if not bp["search"]:
				#if b["addr"] == "oep":
					# DELAY
				if type(bp['addr'])!='int' and bp['addr'].startswith('0x'):
					bp['addr'] = int(b['addr'][2:], 16)

		if 'handlers' in self.options:
			# Stable sort guaranteed
			handler_by_bp = itertools.groupby(sorted(self.options['handlers'], key=operator.itemgetter('bp')), operator.itemgetter('bp'))
			self.handlers = {}
			for i, item in handler_by_bp:
				self.handlers[i] = list(item)

		if 'target' not in self.options:
			raise
		target = self.options['target']
		self.dbg.load(target)
		self.pe = pefile.PE(target)
		self.oep_rva = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		self.fake_base_of_image = self.pe.OPTIONAL_HEADER.ImageBase

		self.options.setdefault('oep', None)
		if self.options['oep'] and type(self.options['oep'])!='int' and self.options['oep'].startswith('0x'):
			self.options['oep'] = int(self.options['oep'], 16)

'''
def parse_options(args):
	parser = argparse.ArgumentParser()
	# Primary general option
	parser.add_argument('--oep', action='store', dest='oep', help='Specify OEP.')
	parser.add_argument('-b', action='store', dest='breakpoint', required=True, help='Breakpoint. API name/Address/"oep", depending on -s', nargs='+')
	parser.add_argument('--no-search', action='store_false', dest='search', default=True, help='Don\'t search for the name, given by -b. Search by default')
	parser.add_argument('-t', action='store', choices=['hardware', 'memory'], dest='type', default='memory', help='Type of breakpoint. Memory by default')
	parser.add_argument('--time', action='store', type=int, dest='time', default='-1', help='Time to live for the handler')
	subparses = parser.add_subparsers(title='Utils', dest='utils', help='USE %(prog)s disable -h OR %(prog)s mitm -h FOR DETAILS')
	# Options for disable module
	parser_disable = subparses.add_parser('disable', help='Disable specified APIs.')
	parser_disable.add_argument('-i', '--interactive', action='store_true', dest='interactive', default=False, help='Prompt before disabling')
	# Options for mitm module
	parser_mitm = subparses.add_parser('mitm', help='Man in the Middle')
	parser_mitm.add_argument('--indirect', action='store_true', dest='indirect', default=False, help='Indirect Address. False by default')
	group = parser_mitm.add_mutually_exclusive_group(required=True)
	group.add_argument('--offset', action='store', dest='offset', help='Bytes offset to the param from esp')
	group.add_argument('--address', action='store', dest='address', help='Absolute address to modify data')
	parser_mitm.add_argument('--length', action='store', type=int, dest='length', help='The length of the continuous memory')
	parser_mitm.add_argument('--into', type=argparse.FileType('r'), default=sys.stdin, dest='into', help='Change bytes into')
	parser_mitm.add_argument('--display', action='store', choices=['%s', '%d', '%l', '%x', '%b'],
								default='%s', dest='display', help='Format of displaying')
	# Options for trace module
	parser_trace = subparses.add_parser('trace', help='Trace the execution of instructions.')
	parser_trace.add_argument('-f', type=argparse.FileType('w'), required=True, action='store', dest='file', help='Output File')
	parser_trace.add_argument('-m', action='append', dest='module', help='Visible Modules')
	#
	parser.add_argument('-l', action='store', dest='log', help='Log filename. Not supported yet.')
	parser.add_argument('-c', action='store', dest='crash-report', help='Crash report filename. Not supported yet.')

	option = parser.parse_args(args)

	# MITM argument check
	if option.utils == 'mitm':
		if option.offset:
			if option.offset.startswith('0x'):
				option.offset = int(option.offset[2:], 16)
			else:
				option.offset = int(option.offset, 16)
			option.r
		elif option.address:
			if option.address.startswith('0x'):
				option.address = int(option.address[2:], 16)
			else:
				option.address = int(option.address, 16)
		else:
			raise
		raw = option.into.read().strip()
		option.into.close()
		option.into = raw
		if  option.display == '%s' and len(option.into)!=option.length:
			sys.stderr.write('[-] Length is incompatible with into')
			exit(0)

	# Translate breakpoint into integer
	if not option.search:
		for i, bp in enumerate(option.breakpoint):
			if bp == 'oep':
				option.search = True
			elif bp.startswith('0x'):
				option.breakpoint[i] = int(bp[2:], 16)
			else:
				option.breakpoint[i] = int(bp)
	return option
'''

if __name__ == '__main__':
	# WTF, sys.argv[0]:win32_sandbox.py???
	#options = parse_options(sys.argv[2:])
	a = sandbox()
	a.load_project(sys.argv[1])
	a.run()
	a.post_process()

	print '[*] Exit'
