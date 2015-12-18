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
		# Initialize key variables
		self.breakpoints = []
		self.handlers = []
		self.global_handlers = []
		self.dbg = pydbg()
		self.plugins = {}

		# The starting work
		self.dbg.set_callback(CREATE_PROCESS_DEBUG_EVENT, self.__create_process_handle)
		# self.__universal_handle takes over single_step (And all other breakpoints later on)
		self.dbg.set_callback(EXCEPTION_SINGLE_STEP, self.__universal_handle)

		# These are the primary plugins
		self._register_new_plugin('disable', self.__disable_handle, None, None)
		# Note that a collide file is shrinked , than a regular trace file
		self._register_new_plugin('trace', self.__trace_start_handle, self.__trace_pre_process, self.__trace_post_process)
		self._register_new_plugin('mitm', self.__mitm_handle, None, None)
		self._register_new_plugin('intercept', self.__intercept_handle, None, None)

	# Register new plugins, can be called in child class, to extend the functionality
	def _register_new_plugin(self, name, handle, pre_process, post_process):
		if name in self.plugins:
			raise NameError
		self.plugins[name] = {'handler':handle, 'pre_process':pre_process, 'post_process':post_process}

	# Run the debugger and the debuggee
	def run(self):
		print '[+] Start debugging'
		self.dbg.run()

	# Disable apis/part of functions by jumping to the ret address
	def __disable_handle(self, dbg, handler):
		eip = dbg.context.Eip
		# Breakpoint doesn't necessarily have a name, empty by default
		func_name = self.breakpoints[handler['bp']]['name']
		print '[+] Banning API: %s\t0x%x' % (func_name, eip)
		ptr = eip
		while True:
			ins = dbg.disasm_around(ptr, 1)
			if ins[1][1].startswith('ret'):
				# jump to retn n, what if there's no retn? there's the chance
				dbg.set_register('EIP', ins[1][0])
				break
			ptr = ins[2][0]
		return DBG_CONTINUE

	# Deal with Runtime function resolve,  which has been filtered by
	# the load time function resolve: self.__dyn_link
	def __gpa_ret_handle(self, dbg):
		# Return value of GetProcAddress
		func_addr = dbg.context.Eax
		func_name = self.last_dyn_API
		for i, bp in enumerate(self.breakpoints):
			# Check if it's not been filtered
			if bp['search'] and not bp['resolved']:
				module, func = bp['addr'].split('@')
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

	# Works with __gpa_ret_handle, because GetProcAddress's return value
	# should be captured in the __gpa_ret_handle
	def __gpa_handle(self, dbg):
		esp = dbg.context.Esp
		ret = struct.unpack('<I', dbg.read(esp, 4))[0]
		func_name_ptr = struct.unpack('<I', dbg.read(esp+8, 4))[0]
		func_name = ''
		try:
			func_name = dbg.read(func_name_ptr, 30)
		except:
			# if func_name exceeded the length, then try shorter name
			for i in range(30, 0, -1):
				try:
					func_name = dbg.read(func_name_ptr, i)
					break
				except:
					pass
		# A functions which cannot detect the name
		# will not be a valid API breakpoint either
		if not func_name:
			return DBG_CONTINUE
		func_name = dbg.get_ascii_string(func_name)
		# Execute Until Return
		dbg.bp_set(ret, restore=False, handler=self.__gpa_ret_handle)
		# THERES THE MULTITHREAD PROBLEM!!!!!!!!!!!!!!!!!!!!!!!!
		# BUT NOT OF A HUGE TROBLE
		# Record the function name so the
		self.last_dyn_API = func_name
		return DBG_CONTINUE

	# STILL FAULTY COMPLETELY!!!!!!!!!!!!!!!!!!!!!!!!!
	# IT'S NEEDED BECAUSE loaded_module and visible_module etc.
	# SHOULD BE UPDATED AT RUNTIME!!!!!!!!!!!!!1
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
	def __mitm_handle(self, dbg, handler):
		eip = dbg.context.Eip
		# two addressing method now. Offset to esp / Absolute VA
		if handler['addressing'] == 'toesp':
			esp = dbg.context.Esp
			addr = esp + handlers['addr']
		elif handler['addressing'] == 'absolute':
			# WRONG!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
			# ALL ADDRESS INPUT FROM PROJ FILE SHOULD BE RELOCATED!!!!!!!!!!!!!!!!!!!!!!!!!
			# IT'S AN ADDRESS
			addr = self.handlers['addr']
		# If indirect specified , lookup address
		if handler['indirect']:
			addr = struct.unpack('<I', dbg.read(addr, 4))[0]

		# mutator should be imported, and INSTANCTIATED!!! duaring __mitm_pre_process

		# provide sufficient context infomation for mutator
		# SO MITM MODULE CARRYING SOME SPECIFIC MUTATOR MUST BE PUT BEFORE TRACE MODULE,
		# OR TRACE MODULE WILL ERASE THE COLLIDE_SET AT FIRST!!!!!!!!!!!!!
		handler['mutator'].set_context(dbg, handler)
		# get request len from mutator
		request_len = handler['mutator'].get_request_length()
		# request memory from debuggee
		request = dbg.read(addr, request_len)
		# get ripe request out of raw
		request = handler['mutator'].cook(request)
		# mutate ripe request into response
		response = handler['mutator'].mutate(request)
		# they must have the same size, or system will thrash
		# an exception: string can terminate earlier
		dbg.write(addr, response, request_len)

		request_display = handler['mutator'].display(request)
		response_display = handler['mutator'].display(response)

		# Strip if too long
		if len(request_display) > 53:
			request_display = request_display[0:50] + '...'
		if len(response_display) > 53:
			response_display = response_display[0:50] + '...'

		if handler['addressing'] == 'toesp':
			print '[+] Param offset to esp %d: %s\n[+] Changed into %s' %
				(handler['address'], request_display, response_display)
		elif handler['addressing'] == 'absolute':
			print '[+] Data at address 0x%x: %s\n[+] Changed into %s' %
				(handler['address'], request_display, response_display)

		'''
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
		'''
		return DBG_CONTINUE

	# All the prepare work before run.
	def __create_process_handle(self, dbg):
		# Get the base of image, to relocate oep
		self.base_of_image = dbg.dbg.u.CreateProcessInfo.lpBaseOfImage
		# If oep is specified in the project file, then relocate it
		if self.options['oep']:
			self.options['oep'] = self.options['oep']-self.fake_base_of_image+self.base_of_image
		# If not, then read and compute from the PE file
		else:
			self.options['oep'] = self.oep_rva + self.base_of_image
		dbg.bp_set(self.options['oep'], restore=False, handler=self.__oep_handle)
		# Prepare work of handlers (and the plugins they classified to)
		for hs in self.handlers.itervalues():
			for h in hs:
				if self.plugins[h['util']]['pre_process']:
					self.plugins[h['util']]['pre_process'](h)
		return DBG_CONTINUE

	# Still prepare work, (Runtime prepare work)
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

	def __relocate_addr_loaded_module(self, addr):
		# Determin which module is 'addr' in
		within = filter(lambda x: x['fake_start']<=addr<=x['fake_start']+x['end']-x['start'], self.loaded_modules.itervalues())
		if not within or len(within) > 1:
			raise
		# Get the va out of fake va
		return addr - within[0]['fake_start'] + within[0]['start']

	# The prepare work of trace plugin
	def __trace_pre_process(self, h):
		# Trace file output, if not specifed, use stdout
		if 'file' in h:
			h['fd'] = open(h['file'], 'w')
		else:
			h['fd'] = sys.stdout
			# set \filename\ to Stdout
			h['file'] = 'Stdout'
		# Collide function of trace
		if 'collide' in h:
			h['collide'].setdefault('coverage_incremental_thredshold', 5)
			h['collide'].setdefault('thredshold_step', 0)
			if 'file' not in h['collide']:
				raise
			with open(h['collide']['file']) as f:
				# Read trace rva into orig_coverage as a set
				h['collide']['orig_coverage'] = set(map(lambda x:int(x.strip().split('\t')[1]), f.read().strip().split('\n')))
				print '[+] Reference coverage information loaded: %s' % h['collide']['file']
			# Clean the collide_set
			h['collide']['collide_set'] = set()
			# At the start of trace, thredshold += thredshold_step, so back to real value
			h['collide']['coverage_incremental_thredshold'] -= h['collide']['thredshold_step']
		# IT'S AN ADDRESS
		if 'until' in h:
			if h['until'].startswith('0x'):
				h['until'] = int(h['until'][2:], 16)
			# RUNTIME BREAKPOINT
			if h['until'] == '@ret':
				pass
			# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!RUNTIME TOO!!!!!!!!!!!!!!!!!!!!
			elif '@' in h['until']:
				module, func = h['until'].split('@')
				module = module.lower()
				h['until'] = sef.dbg.func_resolve_debuggee(module, func)
			# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!RUNTIME TOO!!!!!!!!!!!!!!!!!!!!
			else:
				h['until'] = self.__relocate_addr_loaded_module(h['until'])

		h.setdefault('visible_modules', [])
		# Only program visible by default
		h['visible_modules'].append(os.path.basename(self.options['target']).lower())
		h['inst_stream'] = []
		h['inst_stream_rva'] = []
		# Don't print relay breakpoint ( that is, reused )
		h['relay'] = False
		# Backup the breakpoint of trace, to restore the relayed handler to original
		# when reached 'until' ( on if 'until' specified)
		h['bp_backup'] = self.breakpoints[h['bp']]['addr']

	# The post process of trace, just dump trace/collide file
	def __trace_post_process(self, h):
		h['fd'].write('\n'.join(['0x%x\t%d'%i for i in zip(h['inst_stream'], h['inst_stream_rva'])]))
		print '[+] Tracing file dumped: %s' % h['file']
		h['fd'].close()

	def __trace_main(self, dbg, handler, global_handler=None):
		eip = dbg.context.Eip
		# If within visible modules
		within = filter(lambda x: x['start']<=eip<=x['end'], map(lambda y:self.loaded_modules[y], handler['visible_modules']))
		if not within:
			return False
		if len(within) > 1:
			raise
		# Record the trace file
		handler['inst_stream'].append(eip-within[0]['start']+within[0]['fake_start'])
		handler['inst_stream_rva'].append(eip-within[0]['start'])
		dbg.single_step(True)
		meet = False
		if 'collide' in handler:
			handler['collide']['collide_set'].add(eip-within[0]['start'])
			if len(handler['collide']['collide_set'] - handler['collide']['orig_coverage']) > handler['collide']['coverage_incremental_thredshold']:
				print '[!] Coverage incremental thredshold exceeded!\n\tAnd overlapped 0x%x!' % eip
				# if collide successfully, mute in advance
				meet = True
		# Whether met until
		if 'until' in handler:
			# IT'S AN ADDRESS
			if handler['until'] == '@ret':
				ins = dbg.disasm_around(eip, 0)[0][1]
				if ins.startswith('ret'):
					meet = True
			elif eip == handler['until']:
				meet = True
			if meet:
				print '[+] Traced until: 0x%x\n' % eip
				# restore the (maybe) relayed handler to the original one
				# WRONG !!!!!!!!!!!WHAT IF HARDWARE!!!!!!!!!!!!
				dbg.bp_del(self.breakpoints[handler['bp']]['addr'])
				dbg.bp_set(handler['bp_backup'], restore=False, handler=self.__universal_handle)
				self.breakpoints[handler['bp']]['addr'] = handler['bp_backup']
				if global_handler:
					self.global_handlers.remove(tmp_handler)
				handler['relay'] = False
				# Mute single_step
				dbg.single_step(False)
		return True
	# The real handle of trace, which will start a sub-handler (global)
	def __trace_start_handle(self, dbg, handler):
		eip = dbg.context.Eip
		if not handler['relay']:
			print '[+] Start tracing at: 0x%x' % eip
			if 'collide' in handler:
				# A new cycle with an empty collide_set, and a increased thredshold
				handler['collide']['collide_set'] = set()
				handler['collide']['coverage_incremental_thredshold'] += handler['collide']['thredshold_step']
				print '[+] Start colliding, thredshold: %d' % handler['collide']['coverage_incremental_thread']
		self.__trace_main(dbg, handler, None)
		for thread_id in dbg.enumerate_threads():
			# What's the thread used for???
			h_thread = dbg.open_thread(thread_id)
			dbg.single_step(True, thread_handle=h_thread)
			dbg.close_handle(h_thread)
		# start a sub-handler
		self.global_handlers.append({'handle':self.__trace_handle, 'orig_handler':handler})
		dbg.resume_all_threads()
		return DBG_CONTINUE

	def __intercept_handle(self, dbg, handler):
		pass

	def __trace_handle(self, dbg, tmp_handler):
		eip = dbg.context.Eip
		handler = tmp_handler['orig_handler']
		# If breaked at next instruction successfully
		if self.__trace_main(self, dbg, handler, tmp_handler):
			return DBG_CONTINUE
		# If failed, break at the return address
		esp = dbg.context.Esp
		ret = dbg.read(esp, 4)
		ret = struct.unpack("<I", ret)[0]

		# WILL I MISS SOMETHING THAT STARTS IN OTHER MODULE AND END UP IN VISIBLE ONES????
		if filter(lambda x: x['start']<=ret<=x['end'], map(lambda y:self.loaded_modules[y], handler['visible_modules'])):
			# Reuse the handler
			# Trace should never share a breakpoint with others
			# WRONG !!!!!!!!!!!WHAT IF HARDWARE!!!!!!!!!!!!
			dbg.bp_del(self.breakpoints[handler['bp']]['addr'])
			dbg.bp_set(ret, restore=False, handler=self.__universal_handle)
			self.breakpoints[handler['bp']]['addr'] = ret
			handler['relay'] = True
			self.global_handlers.remove(tmp_handler)
			dbg.single_step(False)
		return DBG_CONTINUE

	# get ImageBase in the optional NT header
	def __getImageBase(self, fname):
		with open(fname) as f:
			# offset of address of NT header
			f.seek(0x3c)
			nt_header=struct.unpack('<I',f.read(4))[0]
			# offset of ImageBase
			f.seek(nt_header + 0x34)
			imagebase=struct.unpack('<I',f.read(4))[0]
			return imagebase

	# All about load-time
	def __dyn_link(self):
		self.loaded_modules = {}

		# SHOULD BE UPDATED
		for module in self.dbg.iterate_modules():
			self.loaded_modules[module.szModule.lower()] = {
					'start'		:module.modBaseAddr,
					'end'		:module.modBaseAddr+module.modBaseSize,
					'fake_start':self.__getImageBase(module.szExePath)
					}
		# IT'S AN ADDRESS
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
				within = filter(lambda x: x['fake_start']<=bp['addr']<=x['fake_start']+x['end']-x['start'], self.loaded_modules.itervalues())
				if not within:
					raise
				tmp = bp['addr']
				bp['addr'] = bp['addr'] - within[0]['fake_start'] + within[0]['start']
				print '[+] Place breakpoint at\t0x%x --> 0x%x (relocated)' % (tmp, bp['addr'])

			if not bp['search'] or bp['resolved']:
				try:
					if bp['type'] == 'hardware':
						self.dbg.bp_set_hw(bp['addr'], 1, HW_EXECUTE, handler=self.__universal_handle)
					else:
						self.dbg.bp_set(bp['addr'], handler=self.__universal_handle)
				except:
					print '[-] Failed to place breakpoint\t0x%x' % bp['addr']

	# The center of breakpoints and handlers
	def __universal_handle(self, dbg):
		eip = dbg.context.Eip
		# Global handlers have no expire now
		for h in self.global_handlers:
			h['handle'](dbg, h)
		# Get breakpoints at eip
		for bp in filter(lambda x:x['addr']==eip and x['time']!=0, self.breakpoints):
			# Get handlers at bp
			handlers = self.handlers[bp['id']]
			# Pre actions of all breakpoints
			if 'pre_action' in bp:
				self.actions[bp['pre_action']](dbg)
			# Each handler called once
			for h in handlers:
				self.plugins[h['util']]['handler'](dbg, h)
			# Post actions of all breakpoints
			if 'post_action' in h:
				self.actions[bp['post_action']](dbg)
			# Expire
			if bp['time'] > 0:
				bp['time'] -= 1
				if bp['time'] == 0:
					print '[*] Handler expired at: %s\t0x%x' % (bp['name'], bp['addr'])
					if bp['time'] == 'hardware':
						self.dbg.bp_del_hw(bp['addr'])
					else:
						self.dbg.bp_del(bp['addr'])
		return DBG_CONTINUE

	# A user interface to dispose all handlers
	# Global handlers have no post_process now
	def post_process(self):
		for hs in self.handlers.itervalues():
			for h in hs:
				if self.plugins[h['util']]['post_process']:
					self.plugins[h['util']]['post_process'](h)

	# Load .json project file
	def load_project(self, fname):
		with open(fname) as f:
			self.options = json.load(f)
		if 'breakpoints' in self.breakpoints:
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
			# IT'S AN ADDRESS
			if not bp["search"]:
				if type(bp['addr'])!='int' and bp['addr'].startswith('0x'):
					bp['addr'] = int(bp['addr'][2:], 16)
		# Index handlers by bp
		# Hanlders dont't implement much operation here because
		# 	many options should be determined at runtime
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
		pe = pefile.PE(target)
		self.oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		self.fake_base_of_image = pe.OPTIONAL_HEADER.ImageBase
		self.options.setdefault('oep', None)

if __name__ == '__main__':
	a = sandbox()
	a.load_project(sys.argv[1])
	a.run()
	a.post_process()

	print '[*] Exit'
