#!/usr/bin/python

from __future__ import print_function

from random import choice
import ui

import sys
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from capstone import *
import argparse

CODENAME = "Super Tux"
VERSION = "1.0 (release)"

instr_ptr = None

decoders = {
	"arm32": (UC_ARCH_ARM, UC_MODE_ARM, UC_ARM_REG_SP, 0x2000, UC_ARM_REG_PC, CS_ARCH_ARM, CS_MODE_ARM),
	"arm_thumb": (UC_ARCH_ARM, UC_MODE_THUMB, UC_ARM_REG_SP, 0x2000, UC_ARM_REG_PC, CS_ARCH_ARM, CS_MODE_THUMB),
	"arm64": (UC_ARCH_ARM64, UC_MODE_ARM, UC_ARM64_REG_SP, 0x2000, UC_ARM64_REG_PC, CS_ARCH_ARM64, CS_MODE_ARM),
	# Disabled, I need to check something about big / little endian	
	#"mips_3": (UC_ARCH_MIPS, UC_MODE_MIPS3, CS_MODE_MIPS3),
	#"mips_32": (UC_ARCH_MIPS, UC_MODE_MIPS32, CS_MODE_MIPS32),
	#"mips_32r6": (UC_ARCH_MIPS, UC_MODE_MIPS32R6, CS_MODE_MIPS32R6),
	#"mips_64": (UC_ARCH_MIPS, UC_MODE_MIPS64, CS_MODE_MIPS64),
	"x86_16": (UC_ARCH_X86, UC_MODE_16, UC_X86_REG_ESP, 0x2000, UC_X86_REG_EIP, CS_ARCH_X86, CS_MODE_16),
	"x86_32": (UC_ARCH_X86, UC_MODE_32, UC_X86_REG_ESP, 0x2000, UC_X86_REG_EIP, CS_ARCH_X86, CS_MODE_32),
	"x86_64": (UC_ARCH_X86, UC_MODE_64, UC_X86_REG_RSP, 0x2000, UC_X86_REG_RIP, CS_ARCH_X86, CS_MODE_64),
}

# Banner files
banners = ["ninja.txt", "ghost01.hwtxt"]

def print_banner():
	banner = choice(banners)
	with open(banner) as f:
		ui.out(f.read())
	ui.out("\nCoded by {{RED}}DeveloppSoft{{CLEAR}} - {{BLUE}}github.com/DeveloppSoft{{CLEAR}}")

def print_version():
	ui.out("\n{{RED}}%s{{CLEAR}} - {{BLUE}}%s{{CLEAR}}" % (VERSION, CODENAME))

class SimpleEngine:
	def __init__(self, arch, mode):
		self.capmd = Cs(arch, mode)

	def disas_single(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			ui.out("\t{{RED}}0x%x:\t{{BLUE}}%s\t{{CYAN}}%s{{CLEAR}}" % (i.address, i.mnemonic, i.op_str))
			break

	def disas_all(self, data, addr):
		for i in self.capmd.disasm(data, addr):
			ui.out("\t{{RED}}0x%x:\t{{BLUE}}%s\t{{CYAN}}%s{{CLEAR}}" % (i.address, i.mnemonic, i.op_str))

# globals for the hooks
write_bounds = [None, None]

def mem_reader(uc, addr, size):
	tmp = uc.mem_read(addr, size)

	for i in tmp:
		ui.raw("\t{{MAGENTA}}0x%x" % i)
	ui.out("{{CLEAR}}")

# bail out on INT 0x3 (0xCC)
def hook_intr(uc, intno, user_data):
	if intno == 0x3:
		return False;
	else:
		return True

def hook_mem_invalid(uc, access, address, size, value, user_data):
	eip = uc.reg_read(instr_ptr)

	if access == UC_MEM_WRITE:
		ui.out("{{RED}}invalid WRITE of {{MAGENTA}}0x%x{{RED}} at {{BLUE}}0x%X{{RED}}, data size = {{CYAN}}%u{{RED}}, data value = {{GREEN}}0x%x{{CLEAR}}" % (address, eip, size, value))
	if access == UC_MEM_READ:
		ui.out("{{RED}}invalid READ of {{MAGENTA}}0x%x{{RED}} at {{BLUE}}0x%X{{RED}}, data size = {{CYAN}}%u{{CLEAR}}" % (address, eip, size))

	return False

def hook_smc_check(uc, access, address, size, value, user_data):
	SMC_BOUND = 0x200
	eip = uc.reg_read(instr_ptr)

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
	ui.out("{{RED}}mem READ:  {{MAGENTA}}0x%x{{RED}}, data size = {{BLUE}}%u{{RED}}, data value = {{CYAN}}0x%x{{CLEAR}}" % (address, size, value))
	print("{{RED}}Printing near deref:{{CLEAR}}")
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
	print_banner()

	parser = argparse.ArgumentParser(description='Decode supplied shellcode automatically with the unicorn engine')
	parser.add_argument('-f', '--file', dest='file', help='file to shellcode binary file', required=False, type=file)
	parser.add_argument('-m', '--mode', dest='mode', help='mode of the emulator (--show-modes)', required=False, default="w86_32")
	parser.add_argument('-i', '--instructions', dest='max_instruction', help='max instructions to emulate', required=False)
	parser.add_argument('-d', '--debug', dest='debug', help='Enable extra hooks for debugging of shellcode', required=False, default=False, action='store_true')
	parser.add_argument('-o', '--output', dest='output', help='Where to write the decoded shellcode', required=False)
	parser.add_argument('-s', '--show-modes', dest='show', action='store_true', help='show available modes and exit', required=False)
	parser.add_argument('-v', '--version', dest='version', action='store_true', help='show version and exit', required=False)

	args = parser.parse_args()

	if args.version:
		print_version()
		sys.exit(0)
	
	if args.show:
		for decoder in decoders:
			ui.out("{{BLUE}}" + decoder + "{{CLEAR}}")
		sys.exit(0)

	if not args.file or not args.mode or args.mode not in decoders:
		ui.error("bad commandline")
		sys.exit(0)

	bin_code = args.file.read()

	const = decoders[args.mode]
	cur_arch = const[0]
	cur_mode = const[1]
	stack_reg = const[2]
	stack_val = const[3]
	instr_ptr = const[4]
	cs_arch = const[5]
	cs_mode = const[6]

	PAGE_SIZE = 5 * 1024 * 1024
	START_RIP = 0x0

	disas_engine = SimpleEngine(cs_arch, cs_mode)

	# setup engine and write the memory there.
	emu = Uc(cur_arch, cur_mode)
	emu.disasm = disas_engine # python is silly but it works.
	emu.mem_map(0, PAGE_SIZE)
	# write machine code to be emulated to memory
	emu.mem_write(START_RIP, bin_code)

	# write a INT 0x3 near the end of the code blob to make sure emulation ends
	emu.mem_write(len(bin_code) + 0xff, "\xcc\xcc\xcc\xcc")

	emu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
	emu.hook_add(UC_HOOK_MEM_WRITE, hook_smc_check)
	emu.hook_add(UC_HOOK_INTR, hook_intr)
	
	if args.debug:
		emu.hook_add(UC_HOOK_MEM_READ, hook_mem_read)
		emu.hook_add(UC_HOOK_CODE, hook_code)

	# arbitrary address for ESP.
	emu.reg_write(stack_reg, stack_val)

	if args.max_instruction:
		end_addr = -1
	else:
		args.max_instruction = 0x1000
		end_addr = len(bin_code)

	try: 
		emu.emu_start(START_RIP, end_addr, 0, int(args.max_instruction))
	except UcError as e:
		ui.bug("%s" % e)

	if write_bounds[0] != None:
		ui.out("{{RED}}Shellcode address ranges:")
		ui.out("   low:  {{BLUE}}0x%X{{RED}}" % write_bounds[0])
		ui.out("   high: {{BLUE}}0x%X{{CLEAR}}\n\n" % write_bounds[1])
		ui.out("{{GREEN}}Decoded shellcode:{{CLEAR}}")
		mem = emu.mem_read(write_bounds[0], (write_bounds[1] - write_bounds[0]))
		emu.disasm.disas_all(str(mem), write_bounds[0])
		# Write the decoded shellcode
		if args.output:
			with open(args.output, "wb") as f:
				f.write(mem)
	else:
		ui.error("no SMC hits, no encoder detected")

if __name__ == '__main__':
	main()
