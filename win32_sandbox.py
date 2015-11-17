from pydbg import *
from pydbg.defines import *
import pefile
import sys
import struct

black_list = []
apis = {}
LastAPI = ''

def ban_handle(dbg):
	eip = dbg.context.Eip
	print '[+] Banning API: %s\t0x%x' % (apis[eip], eip)
	det = 1
	# There should be range detection
	while True:
		ins = dbg.disasm_around(eip, det)[-1]
		if ins[1].startswith('retn'):
			dbg.set_register('EIP', ins[0])
			break
		det += 1
	return DBG_CONTINUE

def gpa_ret_handle(dbg):
	global LastAPI
	func_addr = dbg.context.Eax
	dbg.bp_set(func_addr, handler=ban_handle)
	apis[func_addr] = LastAPI

	return DBG_CONTINUE

def gpa_handle(dbg):
	global LastAPI, black_list
	#print '[*] Breaking on GetProcAddress: 0x%x' % dbg.context.Eip
	esp = dbg.context.Esp
	# 32 elf system only
	ret = struct.unpack("<I", dbg.read(esp, 4))[0]

	func_name_ptr = struct.unpack("<I", dbg.read(esp+8, 4))[0]
	try:
		func_name = dbg.read(func_name_ptr, 50)
	except:
		print '[-] Parsing function at 0x%x failed, ignore' % func_name_ptr
		return DBG_CONTINUE
	func_name = dbg.get_ascii_string(func_name)
	#print func_name

	if func_name in black_list:
		print '[+] Forbidden API detected: %s' % func_name
		# Try to get the result of GetProcAddress, aka &func
		dbg.bp_set(ret, restore=False, handler=gpa_ret_handle)
		LastAPI = func_name
		
	return DBG_CONTINUE
	

def oep_handle(dbg):
	print '[*] Breaking on OEP: 0x%x' % dbg.context.Eip
	parse_iat(pe, dbg)
	getprocaddr = dbg.func_resolve("kernel32.dll", "GetProcAddress")
	dbg.bp_set(getprocaddr, handler=gpa_handle)
	apis[getprocaddr] = "GetProcAddress"
	return DBG_CONTINUE

def parse_iat(pe, dbg):
	global black_list
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		for imp in entry.imports:
			if imp.name in black_list:
				func_name = imp.name
				func_address = dbg.read(imp.address, 4)
				func_address = struct.unpack('<I', func_address)[0]
				print '[+] Forbidden API detected: %s' % func_name
				dbg.bp_set(func_address, handler=ban_handle)
				apis[func_address] = func_name

if __name__ == "__main__":
	file = sys.argv[1]
	black_list = sys.argv[2:]
	pe = pefile.PE(file)
	oep = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint
	dbg = pydbg()
	dbg.load(file)
	dbg.bp_set(oep, handler=oep_handle)
	dbg.run()
	print '[*] Exit'
