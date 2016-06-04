#  Copyright 2016 DeveloppSoft
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

# Contains the constants for the decoder


# Import the constants
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from capstone import *


# The constants !
const = {
	"x86_16": {
		"uc_arch": UC_ARCH_X86,
		"uc_mode": UC_MODE_16,
		"stack": UC_X86_REG_ESP,
		"stack_val": 0x2000,
		"instr": UC_X86_REG_EIP,
		"cs_arch": CS_ARCH_X86,
		"cs_mode": CS_MODE_16
	},
	"x86_32": {
		"uc_arch": UC_ARCH_X86,
		"uc_mode": UC_MODE_32,
		"stack": UC_X86_REG_ESP,
		"stack_val": 0x2000,
		"instr": UC_X86_REG_EIP,
		"cs_arch": CS_ARCH_X86,
		"cs_mode": CS_MODE_32
	},
	"x86_64": {
		"uc_arch": UC_ARCH_X86,
		"uc_mode": UC_MODE_64,
		"stack": UC_X86_REG_RSP,
		"stack_val": 0x2000,
		"instr": UC_X86_REG_RIP,
		"cs_arch": CS_ARCH_X86,
		"cs_mode": CS_MODE_64
	},
	"arm_thumb": {
		"uc_arch": UC_ARCH_ARM,
		"uc_mode": UC_MODE_THUMB,
		"stack": UC_ARM_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_ARM_REG_PC,
		"cs_arch": CS_ARCH_ARM,
		"cs_mode": CS_MODE_THUMB
	},
	"arm32": {
		"uc_arch": UC_ARCH_ARM,
		"uc_mode": UC_MODE_ARM,
		"stack": UC_ARM_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_ARM_REG_PC,
		"cs_arch": CS_ARCH_ARM,
		"cs_mode": CS_MODE_ARM
	},
	"arm64": {
		"uc_arch": UC_ARCH_ARM64,
		"uc_mode": UC_MODE_ARM,
		"stack": UC_ARM_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_ARM_REG_PC,
		"cs_arch": CS_ARCH_ARM,
		"cs_mode": CS_MODE_ARM
	},
	"mips3_big": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS3 + UC_MODE_BIG_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS3 + CS_MODE_BIG_ENDIAN
	},
	"mips32_big": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
	},
	"mips32r6_big": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS32r6 + UC_MODE_BIG_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS32r6 + CS_MODE_BIG_ENDIAN
	},
	"mips64_big": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN
	},
	"mips3_little": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS3 + UC_MODE_LITTLE_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS3 + CS_MODE_LITTLE_ENDIAN
	},
	"mips32_little": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN
	},
	"mips32r6_little": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS32r6 + UC_MODE_LITTLE_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS32r6 + CS_MODE_LITTLE_ENDIAN
	},
	"mips64_little": {
		"uc_arch": UC_ARCH_MIPS,
		"uc_mode": UC_MODE_MIPS64 + UC_MODE_LITTLE_ENDIAN,
		"stack": UC_MIPS_REG_SP,
		"stack_val": 0x2000,
		"instr": UC_MIPS_REG_PC,
		"cs_arch": CS_ARCH_MIPS,
		"cs_mode": CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN
	},
}
