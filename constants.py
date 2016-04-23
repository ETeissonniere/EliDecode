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
	}
}
