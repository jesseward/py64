#!/usr/bin/env python
# I, Danny Milosavljevic, hereby place this file into the public domain.
# -*- coding: utf-8 -*-

# TODO wrap into zero page with IND addressing mode

import mmu
import sys
import tape
import opcodes as op
from symbols import *

def err(message):
    print >>sys.stderr, "error: %s" % message
    sys.exit(1)
    return 42

def to_signed_byte(value):
    return value if value < 0x80 else -(256 - value)


class StatusRegister(object):
    def __init__(self):
        self.C = False  # Indicates when a bit of the result is to 
                        # be carried to, or borrowed from, another byte.
        self.Z = False  # Indicates when the result is equal, or not, to zero.
        self.I = False  # Indicates when preventing, or allowing, non-maskable interrupts
        self.D = False  # Indicates when switching between decimal/binary modes.
        self.B = False  # Indicates when stopping the execution of machine code instructions
        self.NOP = False  # unused SR 
        self.V = False  # Indicates when the result is greater, or less, 
                        # than can be stored in one byte (including sign).
        self.N = False  # Indicates when the result is negative, or positive,
                        # in signed operations.

    def __iter__(self):
        for sr in ['C', 'Z', 'I', 'D', 'B', 'NOP', 'V', 'N']:
            yield (sr, getattr(self, sr))

class Register(object):
    def __init__(self):
        self.PC = 0     # program counter 16 bit data register
        self.SP = 0xFF  # stack pointer 8 bit data register
        self.X = 0      # 8 bit data register
        self.Y = 0      # 8 bit data register
        self.A = 0      # 8 bit data register


class CPU(object):
    def __init__(self):
        self.B_in_interrupt = False
        self.registers = Register()
        self.MMU = mmu.MMU()
        self.SR = StatusRegister()
        self.SR.I = True
        self.SR.Z = True

        if False: # ShedSkin
            value = self.load_value_unadvancing(S_Z)
            value = self.load_value_advancing(S_Z)
            self.update_flags_by_number(value)                 

    def write_register(self, name, value):
        assert isinstance(value, int), "CPU.write_register: value is an integer"
        if name == S_PC:
            self.registers.PC = value
        elif name == S_A:
            self.registers.A = value
        elif name == S_X:
            self.registers.X = value
        elif name == S_Y:
            self.registers.Y = value
        elif name == S_SP:
            self.registers.SP = value
        else:
            assert False, "CPU.write_register: register is known"
        #print("registers", self.registers)

    def read_register(self, name):
        r = self.registers
        return r.PC if name == S_PC else \
               r.A if name == S_A else \
               r.X if name == S_X else \
               r.Y if name == S_Y else \
               r.SP if name == S_SP else \
               err("unknown register")


    def step(self):
        PC = self.read_register(S_PC)
        opcode = self.MMU.read_memory(PC)
        #if PC == 0xE43D:  #FIXME
        # TODO maybe use set_PC so we notice when someone walks into our hooks.
        self.write_register(S_PC, PC + 1)
        #print(hex(opcode), op.instruction_set[opcode].instruction)
        print(hex(opcode))

        # call opcode function
        return getattr(self, op.instruction_set[opcode].instruction)(opcode)


    # TODO DCP {adr} = DEC {adr} + CMP {adr}

    def update_flags_by_number(self, value):
        """ assumes 8 bit number, be careful. """
        assert isinstance(value, int), "CPU.update_flags_by_number: value is a number"
        if value < 0 or ((value & 128) != 0):
            self.SR.N = True
        else:
            self.SR.N = False
        if value == 0:
            self.SR.Z = True
        else:
            self.SR.Z = False
        return value

    def consume_operand(self, size):
        PC = self.read_register(S_PC)
        value = self.MMU.read_memory(PC, size)
        self.write_register(S_PC, PC + size)
        return value

    def consume_unsigned_operand(self, size):
        """ returns the operand as an integer, not as a buffer """
        value = self.consume_operand(size)
        return value

    def consume_signed_operand(self, size):
        """ returns the operand as an integer, not as a buffer """
        value = to_signed_byte(self.consume_operand(size))
        #value = (endian.unpack_signed_16_bit if size == 2 else endian.unpack_signed if size == 1 else err("invalid operand size"))(value)
        #print(value)
        return value

    def read_zero_page_memory(self, address, size = 1):
        assert size < 3, "CPU.read_zero_page_memory: size<3"
        assert size > 0, "CPU.read_zero_page_memory: size>0"
        if size == 2 and address == 0xFF:
            return self.MMU.read_memory(address, 1) | (self.MMU.read_memory(0, 1) << 8)
        else:
            return self.MMU.read_memory(address, size)

    def store_value(self, addressing_mode, value, size = 1):
        #print("MODE", addressing_mode)
        if addressing_mode == op.ZEROPAGE:
            self.MMU.write_memory(self.consume_unsigned_operand(1), value, size)
        elif addressing_mode == op.ZEROPAGE_Y:
            # FIXME unsigned?
            self.MMU.write_memory((self.consume_unsigned_operand(1) + (self.read_register(S_Y)) & 0xFF), value, size)
        elif addressing_mode == op.ZEROPAGE_X:
            # FIXME unsigned?
            self.MMU.write_memory((self.consume_unsigned_operand(1) + (self.read_register(S_X)) & 0xFF), value, size)
        elif addressing_mode == op.ABSOLUTE:
            self.MMU.write_memory(self.consume_unsigned_operand(2), value, size)
        elif addressing_mode == op.ABSOLUTE_Y:
            # FIXME unsigned.
            self.MMU.write_memory((self.consume_unsigned_operand(2) + self.read_register(S_Y)) & 0xFFFF, value, size)
        elif addressing_mode == op.ABSOLUTE_X:
            # FIXME unsigned.
            self.MMU.write_memory((self.consume_unsigned_operand(2) + self.read_register(S_X)) & 0xFFFF, value, size)
        elif addressing_mode == op.INDIRECT_X:
            base = self.consume_unsigned_operand(1)
            # FIXME signed?
            offset = (self.read_register(S_X))
            address = self.MMU.read_memory((base + offset) & 0xFF, 2)
            assert address != 0, "CPU.store_value: debugging sentinel to avoid dereferencing a 0 pointer on IND."
            self.MMU.write_memory(address, value, size)
        elif addressing_mode == op.INDIRECT_Y: # [[$a]+X]
            base = self.consume_unsigned_operand(1)
            #print("base would be $%X" % base)
            address = self.read_zero_page_memory(base, 2)
            # FIXME signed?
            offset = (self.read_register(S_Y))
            #print("address would be $%X+$%X" % (address, offset))
            assert address != 0, "CPU.store_value: debugging sentinel to avoid dereferencing a 0 pointer on IND."
            #print("offset %r" % offset)
            self.MMU.write_memory((address + offset) & 0xFFFF, value, size)
        elif addressing_mode == op.ACCUMULATOR:
            self.write_register(S_A, value)
        else:
            print("error", addressing_mode)
            assert False, "CPU.store_value: addressing mode is known"

    def load_value_unadvancing(self, addressing_mode): # mostly INC and shift instructions...
        old_PC = self.read_register(S_PC)
        result = self.load_value_advancing(addressing_mode)
        self.write_register(S_PC, old_PC)
        return result

    def load_value_advancing(self, addressing_mode):
        # FIXME is unsigned correct?

        value = None
        if addressing_mode == op.ACCUMULATOR:
            value = self.read_register(S_A)

        elif addressing_mode == op.IMMEDIATE:
            value = self.consume_unsigned_operand(1)

        elif addressing_mode == op.ZEROPAGE:
            value = self.MMU.read_zero_page(self.consume_unsigned_operand(1))

        elif addressing_mode == op.ZEROPAGE_X:
            value = self.MMU.read_zero_page((self.consume_unsigned_operand(1) + self.read_register(S_X)) & 0xFF)

        elif addressing_mode == op.ZEROPAGE_Y:
            value = self.MMU.read_zero_page((self.consume_unsigned_operand(1) + self.read_register(S_Y)) & 0xFF)

        elif addressing_mode == op.ABSOLUTE:
            value = self.MMU.read_memory(self.consume_unsigned_operand(2))

        elif addressing_mode == op.ABSOLUTE_X:
            value = self.MMU.read_memory((self.consume_unsigned_operand(2) + self.read_register(S_X)) & 0xFFFF)

        elif addressing_mode == op.ABSOLUTE_Y:
            value = self.MMU.read_memory((self.consume_unsigned_operand(2) + self.read_register(S_Y)) & 0xFFFF)

        elif addressing_mode == op.INDIRECT_X:
            value = self.MMU.read_memory(self.MMU.read_memory((self.consume_unsigned_operand(1) +
                                          self.read_register(S_X)) & 0xFF, 2))

        elif addressing_mode == op.INDIRECT_Y:
            value = self.MMU.read_memory(self.read_zero_page_memory(self.consume_unsigned_operand(1), 2)
                                 + self.read_register(S_Y))

        else:
            err('invalid addressing mode {0:r}'.format(addressing_mode))

        return value


    def LDX(self, opcode = 0xA2):
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        self.write_register(S_X, value)
        self.update_flags_by_number(value)

    def LDY(self, opcode):
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        self.write_register(S_Y, value)
        self.update_flags_by_number(value)

    def LDA(self, opcode):
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        #if value is None:
        #    print("ADR", CPU.LDA_addressing_modes[opcode])
        #print("LDA result is %r" % value)
        self.write_register(S_A, value)
        self.update_flags_by_number(value)

    def compare(self, value, reference_value):
        result = reference_value - value
        self.update_flags_by_number(result)
        #print("CMP RES", result)
        if reference_value >= value:
            self.SR.C = True
        else:
            self.SR.C = False


    def CMP(self, opcode):
        """ compare with A """
        # FIXME negative numbers?
        assert opcode in [0xC1, 0xC5, 0xC9, 0xCD, 0xD1, 0xD5, 0xD9, 0xDD], "CPU.CMP opcode is in known set"
        reference_value = self.read_register(S_A)
        return self.compare(self.load_value_advancing(
                op.instruction_set[opcode].address_id),
            reference_value)


    def CPX(self, opcode):
        """ compare with X """
        reference_value = self.read_register(S_X)
        return self.compare(self.load_value_advancing(
                op.instruction_set[opcode].address_id),
            reference_value)


    def CPY(self, opcode):
        """ compare with Y """
        # FIXME negative numbers?
        reference_value = self.read_register(S_Y)
        return self.compare(self.load_value_advancing(
                    op.instruction_set[opcode].address_id),
            reference_value)

    def add_BCD(self, a, b): # unsigned
        carry = 1 if self.SR.C else 0  
        # N and Z are invalid on 6502
        a0 = a & 0xF
        a1 = a >> 4
        b0 = b & 0xF
        b1 = b >> 4
        r0 = a0 + b0 + carry
        r1 = a1 + b1 + (1 if r0 > 9 else 0)
        if r0 > 9:
            r0 = r0 - 10
        if r1 > 9:
            r1 = r1 - 10
            self.SR.C = True
        else:
            self.SR.C = False
        # TODO overflow.
        value = (r1 << 4) | r0
        self.write_register(S_A, value)
        self.update_flags_by_number(value)
        return value

    def subtract_BCD(self, a, b):
        uncarry = 0 if self.SR.C else 1
        # N and Z are invalid on 6502
        a0 = a & 0xF
        a1 = a >> 4
        b0 = b & 0xF
        b1 = b >> 4
        r0 = a0 - b0 - uncarry
        r1 = a1 - b1 - (1 if r0 < 0 else 0)
        if r0 < 0:
            r0 = 10 + r0
        if r1 < 0:
            r1 = 10 + r1
            self.SR.C = False
        else:
            self.SR.C = True
        # TODO overflow.
        value = (r1 << 4) | r0
        self.write_register(S_A, value)
        self.update_flags_by_number(value)
        return value

    def add(self, operand_0, operand_1):
        carry = 1 if self.SR.C else 0
        value = (operand_0 + operand_1 + carry)
        B_overflow_1 = False
        a_value = value
        if (value & 0xFF) != value: # that is, value>0xFF.
            self.SR.C = True
            B_overflow_1 = True
        else:
            self.SR.C = False
        value = value & 0xFF
        # 0x7F+1 overflow
        # 0x80+0xFF overflow
        B_overflow = ((operand_0 ^ operand_1) & 0x80) == 0 and ((operand_0 ^ value) & 0x80) != 0
        #((operand_0 ^ operand_1) & (operand_0 ^ (value & 0xFF)) & 0x80) != 0
        #B_overflow = ((operand_1 & 0x80) == 0 and (operand_0 & 0x80) == 0 and (value & 0x80) != 0) or \
        #             ((operand_1 & 0x80) != 0 and (operand_0 & 0x80) != 0 and (value & 0x80) == 0)
        if B_overflow:
            self.SR.V = True
        else:
            self.SR.V = False
        #self.store_value(addressing_mode, value)
        self.write_register(S_A, value)
        self.update_flags_by_number(value)
        return value

    def ADC(self, opcode):
        """ add with carry """
        # TODO BCD arithmetic.
        operand_0 = self.read_register(S_A)
        operand_1 = self.load_value_advancing(op.instruction_set[opcode].address_id)
        #print("ADC", operand_0, operand_1)
        if self.SR.D:
            self.add_BCD(operand_0, operand_1)
        else:
            self.add(operand_0, operand_1)
        # for BCD: carry:=result>$99
        # for BCD: N:=value of bit 7


    def SBC(self, opcode):
        """ subtract with carry """
        # TODO BCD arithmetic.
        operand_0 = self.read_register(S_A)
        operand_1 = self.load_value_advancing(op.instruction_set[opcode].address_id)
        if self.SR.D:
            self.subtract_BCD(operand_0, operand_1)
        else:
            self.add(operand_0, operand_1 ^ 0xFF)

    def test_bits(self, addressing_mode):
        reference_value = self.read_register(S_A)
        value = self.load_value_advancing(addressing_mode)
        result = value & reference_value
        return result, value


    def BIT(self, opcode = 0x24):
        """ like AND, but does not store the result (but just the flags). """
        reference_value = self.read_register(S_A)
        result, operand = self.test_bits(op.instruction_set[opcode].address_id)
        self.update_flags_by_number(result)
        if (operand & 64) != 0:
            self.SR.V = True
        else:
            self.SR.V = False
        if (operand & 128) != 0:
            self.SR.N = True
        else:
            self.SR.N = False

    def AND(self, opcode):
        """ AND with A """
        value, operand = self.test_bits(op.instruction_set[opcode].address_id)
        self.write_register(S_A, value)
        self.update_flags_by_number(value)


    def EOR(self, opcode):
        """ exclusive OR """
        reference_value = self.read_register(S_A)
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        result = value ^ reference_value
        self.write_register(S_A, result)
        self.update_flags_by_number(result)


    def ORA(self, opcode = 0x1):
        """ ORA with A """
        reference_value = self.read_register(S_A)
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        result = value | reference_value
        self.write_register(S_A, result)
        self.update_flags_by_number(result)

    def TXS(self, opcode = 0x9A):
        """ transfer X to stack pointer """
        # does NOT set negative flag!
        self.write_register(S_SP, self.read_register(S_X))

    def TAY(self, opcode = 0xA8):
        """ transfer A to Y """
        self.write_register(S_Y, self.update_flags_by_number(self.read_register(S_A)))

    def TYA(self, opcode = 0x98):
        """ transfer Y to A """
        self.write_register(S_A, self.update_flags_by_number(self.read_register(S_Y)))

    def TAX(self, opcode = 0xAA):
        """ transfer A to X """
        self.write_register(S_X, self.update_flags_by_number(self.read_register(S_A)))

    def TSX(self, opcode = 0xBA):
        """ transfer SP to X """
        value = self.update_flags_by_number(self.read_register(S_SP))
        self.write_register(S_X, value)

    def TXA(self, opcode = 0x8A):
        """ transfer X to A """
        self.write_register(S_A, self.update_flags_by_number(self.read_register(S_X)))

    def CLD(self, opcode = 0xD8):
        """ Clear Decimal """
        self.SR.D = False

    def SED(self, opcode = 0xF8):
        """ Set Decimal """
        self.SR.D = True

    NOP_addressing_modes = {
            0xEA: op.ACCUMULATOR,
            0x1A: op.ACCUMULATOR,
            0x3A: op.ACCUMULATOR,
            0x5A: op.ACCUMULATOR,
            0x7A: op.ACCUMULATOR,
            0xDA: op.ACCUMULATOR,
            0xFA: op.ACCUMULATOR,
            0x04: op.ZEROPAGE,
            0x44: op.ZEROPAGE,
            0x64: op.ZEROPAGE,
            0x0C: op.ABSOLUTE,
            0x1C: op.ABSOLUTE_X,
            0x3C: op.ABSOLUTE_X,
            0x5C: op.ABSOLUTE_X,
            0x7C: op.ABSOLUTE_X,
            0xDC: op.ABSOLUTE_X,
            0xFC: op.ABSOLUTE_X,
            0x9B: op.ABSOLUTE_Y, # C64DTV
            0x14: op.ZEROPAGE_X,
            0x34: op.ZEROPAGE_X,
            0x54: op.ZEROPAGE_X,
            0x74: op.ZEROPAGE_X,
            0xD4: op.ZEROPAGE_X,
            0xF4: op.ZEROPAGE_X,
            0x80: op.IMMEDIATE,
            0x82: op.IMMEDIATE,
            0x89: op.IMMEDIATE,
            0xC2: op.IMMEDIATE,
            0xE2: op.IMMEDIATE,
    }
    def NOP(self, opcode):
        """ No operation """
        value = self.load_value_advancing(op.instruction_set[opcode].address_id)
        #self.consume_operand(1) # dummy so you can replace any 1-arg instruction's opcode by BRK.

    def DEX(self, opcode):
        result = (self.read_register(S_X) - 1) & 0xFF
        self.write_register(S_X, result)
        self.update_flags_by_number(result)

    def INX(self, opcode = 0xE8):
        result = ((self.read_register(S_X)) + 1) & 0xFF
        self.write_register(S_X, result)
        self.update_flags_by_number(result)

    def DEY(self, opcode = 0x88):
        result = (self.read_register(S_Y) - 1) & 0xFF
        self.write_register(S_Y, result)
        self.update_flags_by_number(result)

    def INY(self, opcode = 0xC8):
        result = ((self.read_register(S_Y)) + 1) & 0xFF
        self.write_register(S_Y, result)
        self.update_flags_by_number(result)


    def DEC(self, opcode = 0xC6):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        result = (value - 1) & 0xFF
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)


    def DCP(self, opcode = 0xC3):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        result = (value - 1) & 0xFF
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)
        self.compare(result, self.read_register(S_A))


    def INC(self, opcode):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        result = (value + 1) & 0xFF
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)

    def ASL(self, opcode):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        if (value & 128) != 0:
            self.SR.C = True
        else:
            self.SR.C = False
        result = (value << 1) & 0xFF
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)

    def LSR(self, opcode):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        if (value & 1) != 0:
            self.SR.C = True
        else:
            self.SR.C = False
        result = (value >> 1) & 0xFF
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)


    def ROL(self, opcode):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        value = ((value << 1) | (1 if self.SR.C else 0))
        result = value & 0xFF
        if (value & 0x100) != 0:
            self.SR.C = True
        else:
            self.SR.C = False

        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)

    def ROR(self, opcode = 0x66):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        result = ((value >> 1) | (128 if self.SR.C else 0)) & 0xFF
        if (value & 1) != 0:
            self.SR.C = True
        else:
            self.SR.C = False
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)

    def ROR(self, opcode = 0x66):
        value = self.load_value_unadvancing(op.instruction_set[opcode].address_id)
        result = ((value >> 1) | (128 if self.SR.C else 0)) & 0xFF
        if (value & 1) != 0:
            self.SR.C = True
        else:
            self.SR.C = False
        self.store_value(op.instruction_set[opcode].address_id, result)
        self.update_flags_by_number(result)
    
    def pop_status(self):
        flags_bin = self.stack_pop(1)
        for flag_bit, flag_name in enumerate(self.SR):
            if flags_bin & (1 << flag_bit) != 0:
              setattr(self.SR, flag_name[0], True)
            else:
              setattr(self.SR, flag_name[0], False)

    def push_status(self):
        push = 0
        for flag_bit, flag_name in enumerate(self.SR):
            if getattr(self.SR, flag_name[0]) == True:
                push += 1 << flag_bit
        self.stack_push(push, 1)


    def stack_push(self, value, size):
        """
        actually:
        RAM[sp+256] = value >> 8
        sp_1=sp-1
        sp_1&=255
        RAM[sp-1+256] = value & 0xFF
        sp_2=sp_1-1
        sp_2&=255
        """
        assert isinstance(value, int), "CPU.stack_push: value is an integer"
        SP = self.read_register(S_SP)
        base = 0x100
        for i in range(size): # easier debugging when it doesn't skip slots.
            SP -= 1
            self.write_register(S_SP, SP)
        #SP -= size
        #self.write_register(S_SP, SP)
        address = base + SP + 1
        self.MMU.write_memory(address, value, size)

    def stack_peek(self, size):
        SP = self.read_register(S_SP)
        base = 0x100
        value_bin = self.MMU.read_memory(base + SP + 1, size)
        return value_bin

    def stack_pop(self, size):
        value_bin = self.stack_peek(size)
        SP = self.read_register(S_SP)
        self.write_register(S_SP, SP + size)
        base = 0x100
        #print("stack peek %r" % self.stack_peek(2))
        return value_bin

    def set_PC(self, new_PC):
        self.write_register(S_PC, new_PC)

    def BNE(self, opcode):
        offset = self.consume_signed_operand(1)
        if not self.SR.Z:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BEQ(self, opcode):
        offset = self.consume_signed_operand(1)
        if self.SR.Z:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BPL(self, opcode = 0x10):
        offset = self.consume_signed_operand(1)
        if not self.SR.N:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BMI(self, opcode = 0x30):
        offset = self.consume_signed_operand(1)
        if self.SR.N:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BCS(self, opcode = 0xB0):
        offset = self.consume_signed_operand(1)
        if self.SR.C:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BCC(self, opcode):
        offset = self.consume_signed_operand(1)
        if not self.SR.C:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BVS(self, opcode):
        offset = self.consume_signed_operand(1)
        if self.SR.V:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)

    def BVC(self, opcode):
        offset = self.consume_signed_operand(1)
        if not self.SR.V:
            #print("OFFSET", offset)
            self.set_PC((self.read_register(S_PC) + offset) & 0xFFFF)


    def JMP(self, opcode = 0x4C):
        address = self.consume_unsigned_operand(2)
        if opcode == 0x6C: # indirect jump
            address = self.MMU.read_memory(address, 2)
        self.set_PC(address)


    def JSR(self, opcode = 0x20):
        assert opcode == 0x20, "CPU.JSR: opcode is known"
        #self.push_status()
        new_PC = self.consume_unsigned_operand(2)
        self.stack_push(self.read_register(S_PC) - 1, 2)
        self.set_PC(new_PC)


    def STX(self, opcode):
        """ store X into memory """
        self.store_value(op.instruction_set[opcode].address_id, self.read_register(S_X))


    def STY(self, opcode):
        """ store Y into memory """
        self.store_value(op.instruction_set[opcode].address_id, self.read_register(S_Y))


    def STA(self, opcode = 0x81):
        """ store A into memory """
        self.store_value(op.instruction_set[opcode].address_id, self.read_register(S_A))

    def RTS(self, opcode = 0x60):
        """ return from subroutine """
        PC = (self.stack_pop(2))
        self.set_PC(PC + 1)
        #self.pop_status()

    def RTI(self, opcode = 0x40):
        """ return from interrupt """
        self.pop_status()
        PC = (self.stack_pop(2))
        self.B_in_interrupt = False
        self.set_PC(PC)

    def SEI(self, opcode = 0x78):
        """ Set Interrupt Disable """
        self.SR.I = True

    def CLI(self, opcode = 0x58):
        """ Clear Interrupt Disable """
        self.SR.I = False

    def clear_Z(self): # mostly for unit tests.
        self.SR.Z = False

#    def set_Z(self): # mostly for unit tests.
#        self.flags.add("Z")

#    def clear_N(self): # mostly for unit tests.
#        self.flags.discard("N")

#    def set_N(self): # mostly for unit tests.
#        self.flags.add("N")

#    def set_V(self): # mostly for unit tests.
#        self.flags.add("V")

    def CLC(self, opcode = 0x18):
        """ Clear Carry """
        self.SR.C = False

    def SEC(self, opcode = 0x38):
        """ Set Carry """
        self.SR.C = True

    def CLV(self, opcode = 0xB8):
        """ Clear Overflow """
        self.SR.V = False

    def BRK(self, opcode):
        """ software debugging (NMI) """
        self.consume_operand(1) # dummy so you can replace any 1-arg instruction's opcode by BRK.
        old_PC = self.read_register(S_PC)
        if old_PC - 2 == 0xF8A1 or old_PC - 2 == 0xF7BE or old_PC - 2 == 0xF72F: # tape
            tape.call_hook(self, self.MMU, old_PC - 2)
        else:
            self.cause_interrupt(True)

    def cause_interrupt(self, B_BRK):  # IRQ and BRK.
        if self.B_in_interrupt:
            return
        self.B_in_interrupt = True
        address = 0xFFFE
        old_PC = self.read_register(S_PC)
        self.stack_push(old_PC, 2)
        new_PC = self.MMU.read_memory(address, 2)
        self.push_status()
        self.SEI(0x78)
        #print("NEW PC $%X" % new_PC)
        if B_BRK:
            self.SR.B = True
        self.set_PC(new_PC)

    def PHP(self, opcode):
        """ push processor status """
        self.push_status()

    def PLP(self, opcode):
        """ pull processor status """
        self.pop_status()

    def PHA(self, opcode):
        """ push A """
        self.stack_push(self.read_register(S_A), 1)

    def PLA(self, opcode):
        """ pull A """
        value = self.stack_pop(1)
        self.write_register(S_A, value)
        self.update_flags_by_number(value)

    def AHX(self, opcode):
        raise NotImplementedError("AHX not implemented")
        sys.exit(1)

    def ALR(self, opcode):
        raise NotImplementedError("ALR not implemented")
        sys.exit(1)

    def ANC(self, opcode):
        raise NotImplementedError("ANC not implemented")
        sys.exit(1)

    def ARR(self, opcode):
        raise NotImplementedError("ARR not implemented")
        sys.exit(1)

    def AXS(self, opcode = 0xCB):
        raise NotImplementedError("AXS not implemented")
        sys.exit(1)

    def ISC(self, opcode):
        PC = self.read_register(S_PC)
        print("PC")
        print(PC)
        sys.stdout.flush()
        raise NotImplementedError("ISC not implemented")
        sys.exit(1) # INC whatever; SBC whatever
        # EF abcd
        # FF abcd,X
        # FB abcd,Y
        # E7 ab
        # F7 ab,X
        # E3 (ab,X)
        # F3 (ab),Y
    def KIL(self, opcode):
        raise NotImplementedError("KIL not implemented")
        sys.exit(1)

    def LAS(self, opcode):
        raise NotImplementedError("LAS not implemented")
        sys.exit(1)

    LAX_addressing_modes = {
            0xA3: S_HASH,
            0xA7: S_Z,
            0xB7: S_Z_Y,
            0xAF: S_ABS,
            0xBF: S_ABS_Y,
        }
    def LAX(self, opcode):
        addressing_mode = CPU.LAX_addressing_modes[opcode]
        value = self.load_value_advancing(addressing_mode)
        #if value is None:
        #    print("ADR", CPU.LDA_addressing_modes[opcode])
        #print("LDA result is %r" % value)
        self.write_register(S_A, value)
        self.write_register(S_X, value)
        self.update_flags_by_number(value)

    def RLA(self, opcode):
        raise NotImplementedError("RLA not implemented")
        sys.exit(1)

    def RRA(self, opcode):
        raise NotImplementedError("RRA not implemented")
        sys.exit(1)

    def SAX(self, opcode):
        raise NotImplementedError("SAX not implemented")
        sys.exit(1)

    def SHX(self, opcode):
        raise NotImplementedError("SHX not implemented")
        sys.exit(1)

    def SHY(self, opcode):
        raise NotImplementedError("SHY not implemented")
        sys.exit(1)

    def SLO(self, opcode):
        raise NotImplementedError("SLO not implemented")
        sys.exit(1)

    def SRE(self, opcode):
        raise NotImplementedError("SRE not implemented")
        sys.exit(1)

    def TAS(self, opcode = 0x9B):
        raise NotImplementedError("TAS not implemented")
        sys.exit(1)

    def XAA(self, opcode):
        raise NotImplementedError("XAA not implemented")
        sys.exit(1)


if __name__ == "__main__":
    CPU_1 = CPU()
    #CPU_1.write_register(S_PC, 0)
    #CPU_1.INC(0xE6)
    #print(CPU_1.read_register(S_PC))
    value = open(sys.argv[1], "rb").read()
    for i in range(len(value)):
        CPU_1.MMU.write_memory(i, ord(value[i]), 1)
    PC = 0
    for i in range(100):
        CPU_1.step()
