#!/usr/bin/python3

# Ignored if python 3
from __future__ import print_function

VERSION = "1.2r"
CODENAME = "Phoenix"

import sys

from unicorn import *
from capstone import *

from constants import const

import argparse


class SimpleEngine:
	def __init__(self, const):
		cs_arch = const["cs_arch"]
		cs_mode = const["cs_mode"]
		self.capmd = Cs(cs_arch, cs_mode)

	def disas_single(self, data, addr):
		self.disas_all(data, addr, 1)

	# We use -1 since bool(-1) is False because python2's false is different from python2's False
	def disas_all(self, data, addr, single=0):
		if sys.version[0] != "2":
			# We need to encode the data or we will have a TypeError
			# UTF-8 should be the best one
			data = data.encode("utf-8")
		for i in self.capmd.disasm(data, addr):
			print("  0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
			if single:
				break

# globals for the hooks
write_bounds = [None, None]

def mem_reader(uc, addr, size):
	tmp = uc.mem_read(addr, size)

	for i in tmp:
		print("   0x%x" % i, end="")
	print("")

# bail out on INT 0x3 (0xCC)
def hook_intr(uc, intno, user_data):
	if intno == 0x3:
		return False;
	else:
		return True

def hook_mem_invalid(uc, access, address, size, value, user_data):
	eip = uc.reg_read(uc.eli_const["instr"])

	if access == UC_MEM_WRITE:
		print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
	if access == UC_MEM_READ:
		print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))

	return False

def hook_smc_check(uc, access, address, size, value, user_data):
	SMC_BOUND = 0x200
	eip = uc.reg_read(uc.eli_const["instr"])

	# Just check if the write target addr is near EIP
	if abs(eip - address) < SMC_BOUND:
		if write_bounds[0] == None:
			write_bounds[0] = address
			write_bounds[1] = address
		elif address < write_bounds[0]:
			write_bounds[0] = address
		elif address > write_bounds[1]:
			write_bounds[1] = address

def hook_mem_read(uc, access, address, size, value, user_data):
	print("mem READ:  0x%x, data size = %u, data value = 0x%x" % (address, size, value))
	print("Printing near deref:")
	mem_reader(uc, address, 32)

	return True

def hook_code(uc, addr, size, user_data):
	mem = uc.mem_read(addr, size)
	uc.disasm.disas_single(str(mem), addr)
	return True

# Using new JIT blocks as a heuristic could really add to the simple SMC system if implemented correctly.
# TODO: attempt to make a new-block based heuristic, I am thinking repeated addresses / size of blocks, 
# maybe even disasm them and poke around.

def main():
	# Print version banner
	print("EliDecode started!")
	print("Version: " + VERSION)
	print("Codename: " + CODENAME)
	print("Author: DeveloppSoft")
	print("License: GNU GPL")
	print("")

	parser = argparse.ArgumentParser(description='Decode supplied x86 / x64 shellcode automatically with the unicorn engine')
	parser.add_argument('-f', '--file', dest='file', help='file to shellcode binary file', required=False)
	parser.add_argument('-m', '--mode', dest='mode', help='mode of the emulator (use --show-modes to have a list)', required=False, default="x86_32")
	parser.add_argument('-i', '--instructions', dest='max_instruction', help='max instructions to emulate', required=False)
	parser.add_argument('-d', '--debug', dest='debug', help='enable extra hooks for debugging of shellcode', required=False, default=False, action='store_true')
	parser.add_argument('-s', '--show-modes', dest='show_modes', help='list the modes', required=False, action="store_true")
	parser.add_argument('-o', '--output', dest='output', help='write the binary dump of the decoded shellcode', required=False)

	args = parser.parse_args()
	
	if args.show_modes:
		for mode in const:
			print(mode)
		sys.exit(0)
	
	if not args.file or not args.mode:
		print("Bad commandline, try --help")
		sys.exit(1)

	try:
		with open(args.file, "rb") as file:
			bin_code = file.read()
	except FileNotFoundError:
		print("File not found")
		sys.exit(-1)

	disas_engine = SimpleEngine(const[args.mode])

	uc_arch = const[args.mode]["uc_arch"]
	uc_mode = const[args.mode]["uc_mode"]

	PAGE_SIZE = 2 * 1024 * 1024
	START_RIP = 0x0

	# setup engine and write the memory there.
	emu = Uc(uc_arch, uc_mode)
	emu.disasm = disas_engine # python is silly but it works.
	emu.eli_const = const[args.mode]
	emu.mem_map(0, PAGE_SIZE)
	# write machine code to be emulated to memory
	emu.mem_write(START_RIP, bin_code)

	# write a INT 0x3 near the end of the code blob to make sure emulation ends
	emu.mem_write(len(bin_code) + 0xff, b"\xcc\xcc\xcc\xcc")

	emu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
	emu.hook_add(UC_HOOK_MEM_WRITE, hook_smc_check)
	emu.hook_add(UC_HOOK_INTR, hook_intr)
	
	if args.debug:
		emu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
		emu.hook_add(UC_HOOK_CODE, hook_code)

	# arbitrary address for ESP.
	emu.reg_write(const[args.mode]["stack"], const[args.mode]["stack_val"])

	if args.max_instruction:
		end_addr = -1
	else:
		args.max_instruction = 0x1000
		end_addr = len(bin_code)

	try: 
		emu.emu_start(START_RIP, end_addr, 0, int(args.max_instruction))
	except UcError as e:
		print("ERROR: %s" % e)

	if write_bounds[0] != None:
		print("Shellcode address ranges:")
		print("   low:  0x%X" % write_bounds[0])
		print("   high: 0x%X" % write_bounds[1])
		print("")
		print("Decoded shellcode:")
		mem = emu.mem_read(write_bounds[0], (write_bounds[1] - write_bounds[0]))
		emu.disasm.disas_all(str(mem), write_bounds[0])
		if args.output:
			with open(args.output, "wb") as f:
				f.write(mem)
			print("Wrote %s bytes in %s" % (str(len(mem)), args.output))
	else:
		print("No SMC hits, no encoder detected")

if __name__ == '__main__':
	main()

