##
# FusionX LLC
# David D. Rude II
# April 05 2014
#
# counterfeit - a pykd script which allows for allocations inside the debugged
# process using various protections, this helps to prototype exploitation of
# memory corruption and use-after-free vulnerabilities in applications that
# provide relative freedom over memory operations such as allocate and free
#
# Currently only 32 bit x86 is supported
##

import pykd
import argparse
from ctypes import *

PROCESS_ALL_ACCESS     = (0x000F0000 | 0x00100000 | 0xFFF)

MEM_COMMIT             = 0x1000
MEM_RESERVE            = 0x2000

PAGE_READ              = 0x02
PAGE_READWRITE         = 0x04
PAGE_EXECUTE_READWRITE = 0x40
PAGE_NOACCESS          = 0x01

kernel32 = windll.kernel32

class counterfeit():
	def __init__(self):
		self.pid = pykd.getCurrentProcessId()
		self.hprocess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

	def banner(self):
		'''
		Print the banner.
		'''
		logo = ("                           __                 _____      .__  __   \n"
		"  ____  ____  __ __  _____/  |_  ____________/ ____\\____ |__|/  |_ \n"
		"_/ ___\\/  _ \\|  |  \\/    \\   __\\/ __ \\_  __ \\   __\\/ __ \\|  \\   __\\\n"
		"\\  \__(  <_> )  |  /   |  \\  | \\  ___/|  | \\/|  | \  ___/|  ||  |  \n"
		" \\___  >____/|____/|___|  /__|  \\___  >__|   |__|  \___  >__||__|  \n"
		"     \\/                 \\/          \\/                 \\/\n"
	 	"            version 1.0 - bannedit\n\n")
		print logo
		return

	def VirtualAllocEx(self, lpAddress, dwSize, flAllocationType, flProtect):
		'''
		Allocate memory inside the debugged process with flProtect permissions.
		See the VirtualAllocEx MSDN Documentation for more details.
		'''
		self.size = dwSize
		addr = kernel32.VirtualAllocEx(self.hprocess, lpAddress, dwSize, flAllocationType, flProtect)
		return addr

	def VirtualProtectEx(self, lpAddress, dwSize, flNewProtect, flOldProtect = 0):
		'''
		Change the page permissions for a given memory address.
		'''
		self.size = dwSize
		flOldProtect = byref(create_string_buffer("\x00" * 4))
		ret = kernel32.VirtualProtectEx(self.hprocess, lpAddress, dwSize, flNewProtect, flOldProtect)

		if not ret:
			print "VirtualProtectEx failed"

		return flOldProtect

	def fill_pattern(self, address):
		'''
		Fill the memory with a pattern from 0x41 - (0x41 + dwSize).
		dwSize represents the allocated size or the size given to
		VirtualProtectEx.
		'''
		start = address
		end = address + self.size
		vaddr = start
		dword = 0x41414141

		while vaddr != end:
			pykd.dbgCommand("ed %08x %08x" % (dword, vaddr))
			dword += 1
			vaddr += 4

def main():
	desc = "counterfeit v1.0 - handy script to prototype exploitation of memory corruption and use-after-free vulnerabilities"
	parser = argparse.ArgumentParser(description = desc,
				usage='%(prog)s [options]')
	parser.add_argument("-a", dest = "alloc", metavar = "size", help = "Allocate memory RWX")
	parser.add_argument("-p", dest = "protect", metavar = ("addr", "size", "protect"), nargs = 3, 
				help = "Change page permissions ['r', 'rwx', 'none']")
	parser.add_argument("-f", "--fill", action = "store_true",  help = "Fill the memory with a pattern")

	args = parser.parse_args()
	cf = counterfeit()
	cf.banner()
	print args

	if args.alloc:
		addr = cf.VirtualAllocEx(0, int(args.allocate, 16), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
		if args.fill:
			cf.fill_pattern(addr)
		print "Allocated memory @ 0x%08x with RWX permissions.\n" % addr
		return

	if args.protect:
		address, size, protection = args.protect
		if (protection == 'r'):
			flProtect = PAGE_READ
		elif (protection == 'rw'):
			flProtect = PAGE_READWRITE
		elif (protection == 'rwx'):
			flProtect = PAGE_EXECUTE_READWRITE
		elif (protection == 'none'):
			flProtect = PAGE_NOACCESS
		else:
			# Default to PAGE_NOACCESS
			flProtect = PAGE_NOACCESS

		cf.VirtualProtectEx(int(address, 16), int(size, 16), flProtect, 0)
		if args.fill:
			cf.fill_pattern(int(address, 16))
		print "Changed permissions for memory @ 0x%08x to '%s'\n" % (int(address, 16), protection)
		return

	if not args.alloc and not args.protect:
		parser.print_help()

if __name__ == "__main__":
	main()