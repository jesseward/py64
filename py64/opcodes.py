

class OpType(object):
    """ Container for the 6510 instruction set. """
    def __init__(self, op_code=0x00, instruction='NOP', address_id=0, size=0, cycles=0):
        self.op_code = hex(op_code)
        self.instruction = instruction
        self.address_id = address_id
        self.size = size
        self.cycles = cycles

    def __repr__(self):
        return '<OpType op_code="{0.op_code}, instruction="{0.instruction}"'.format(
                self)

# Addressing modes for the 6510
ABSOLUTE = 0x800
ABSOLUTE_X = 0x809
ABSOLUTE_Y = 0x80F
ACCUMULATOR = ord('A')
IMMEDIATE = ord('#')
IMPLIED = ord('#')
INDIRECT = 7
INDIRECT_X = 0x1D9
INDIRECT_Y = 0x1DF
RELATIVE = 10
ZEROPAGE = 0x200
ZEROPAGE_X = 0x209
ZEROPAGE_Y = 0x20F
NONE = 0x0000

# 6510 instruction set. transposed from 
# https://raw.githubusercontent.com/jesseward/py64/master/resources/Commodore_64_Programmers_Reference_Guide.txt
# Section 242   BASIC TO MACHINE LANGUAGE

instruction_set = {

    # ADC Add memory to ACCUMULATOR with carry
    0x69: OpType(op_code=0x69, instruction='ADC', address_id=IMMEDIATE, size=2, cycles=2),
    0x65: OpType(op_code=0x65, instruction='ADC', address_id=ZEROPAGE, size=2, cycles=3),
    0x75: OpType(op_code=0x75, instruction='ADC', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x6D: OpType(op_code=0x6D, instruction='ADC', address_id=ABSOLUTE, size=3, cycles=4),
    0x7D: OpType(op_code=0x7D, instruction='ADC', address_id=ABSOLUTE_X, size=3, cycles=4),
    0x79: OpType(op_code=0x79, instruction='ADC', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0x61: OpType(op_code=0x61, instruction='ADC', address_id=INDIRECT_X, size=2, cycles=6),
    0x71: OpType(op_code=0x71, instruction='ADC', address_id=INDIRECT_Y, size=2, cycles=5),

    # AND memory with ACCUMULATOR
    0x29: OpType(op_code=0x29, instruction='AND', address_id=IMMEDIATE, size=2, cycles=2),
    0x25: OpType(op_code=0x25, instruction='AND', address_id=ZEROPAGE, size=2, cycles=3),
    0x35: OpType(op_code=0x35, instruction='AND', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x2D: OpType(op_code=0x2D, instruction='AND', address_id=ABSOLUTE, size=3, cycles=4),
    0x3D: OpType(op_code=0x3D, instruction='AND', address_id=ABSOLUTE_X, size=3, cycles=4),
    0x39: OpType(op_code=0x39, instruction='AND', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0x21: OpType(op_code=0x21, instruction='AND', address_id=INDIRECT_X, size=2, cycles=6),
    0x31: OpType(op_code=0x31, instruction='AND', address_id=INDIRECT_Y, size=2, cycles=5),

    # ASL Shift Left One Bit (Memory or Accumulator)
    0x0A: OpType(op_code=0x0A, instruction='ASL', address_id=ACCUMULATOR, size=1, cycles=2),
    0x06: OpType(op_code=0x06, instruction='ASL', address_id=ZEROPAGE, size=2, cycles=5),
    0x16: OpType(op_code=0x16, instruction='ASL', address_id=ZEROPAGE_X, size=2, cycles=6),
    0x0E: OpType(op_code=0x0E, instruction='ASL', address_id=ABSOLUTE, size=3, cycles=6),
    0x1E: OpType(op_code=0x1E, instruction='ASL', address_id=ABSOLUTE_X, size=3, cycles=7),

    # BCC Branch on Carry Clear
    0x90: OpType(op_code=0x90, instruction='BCC', address_id=RELATIVE, size=2, cycles=2),
    
    # BCS Branch on carry set
    0xB0: OpType(op_code=0xB0, instruction='BCS', address_id=RELATIVE, size=2, cycles=2),

    # BEQ Branch on result zero
    0xF0: OpType(op_code=0xF0, instruction='BEQ', address_id=RELATIVE, size=2, cycles=2),

    # BIT Test bits in memory with ACCUMULATOR
    0x24: OpType(op_code=0x24, instruction='BIT', address_id=ZEROPAGE, size=2, cycles=3),
    0x2C: OpType(op_code=0x2C, instruction='BIT', address_id=ABSOLUTE, size=3, cycles=4),

    # BMI Branch on result minus
    0x30: OpType(op_code=0x30, instruction='BMI', address_id=RELATIVE, size=2, cycles=2),

    # BNE Branch on result not zero
    # TODO: verify.
    0xD0: OpType(op_code=0xD0, instruction='BNE', address_id=RELATIVE, size=2, cycles=2),

    # BPL Branch on result plus
    0x10: OpType(op_code=0x10, instruction='BPL', address_id=RELATIVE, size=2, cycles=2),

    # BRK Force Break
    0x00: OpType(op_code=0x00, instruction='BRK', address_id=IMPLIED, size=1, cycles=7),

    # BVC Branch on overflow clear
    0x50: OpType(op_code=0x50, instruction='BVC', address_id=RELATIVE, size=2, cycles=2),

    # BVS Branch on overflow set
    0x70: OpType(op_code=0x70, instruction='BVS', address_id=RELATIVE, size=2, cycles=2),

    # CLC Clear carry flag
    0x18: OpType(op_code=0x18, instruction='CLC', address_id=IMPLIED, size=1, cycles=2),

    # CLD Clear decimal mode
    0xD8: OpType(op_code=0xD8, instruction='CLD', address_id=IMPLIED, size=1, cycles=2),

    # CLI Clear interrupt disable bit
    0x58: OpType(op_code=0x58, instruction='CLI', address_id=IMPLIED, size=1, cycles=2),

    # CLV Clear overflow flag
    0xB8: OpType(op_code=0xB8, instruction='CLV', address_id=IMPLIED, size=1, cycles=2),

    # CMP Compare memory and ACCUMULATOR
    0xC9: OpType(op_code=0xC9, instruction='CMP', address_id=IMPLIED, size=2, cycles=2),
    0xC5: OpType(op_code=0xC5, instruction='CMP', address_id=ZEROPAGE, size=2, cycles=3),
    0xD5: OpType(op_code=0xD5, instruction='CMP', address_id=ZEROPAGE_X, size=2, cycles=4),
    0xCD: OpType(op_code=0xCD, instruction='CMP', address_id=ABSOLUTE, size=3, cycles=4),
    0xDD: OpType(op_code=0xDD, instruction='CMP', address_id=ABSOLUTE_X, size=3, cycles=4),
    0xD9: OpType(op_code=0xD9, instruction='CMP', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0xC1: OpType(op_code=0xC1, instruction='CMP', address_id=INDIRECT_X, size=2, cycles=6),
    0xD1: OpType(op_code=0xD1, instruction='CMP', address_id=INDIRECT_Y, size=2, cycles=5),

    # CPX Compare Memory and Index X
    0xE0: OpType(op_code=0xE0, instruction='CPX', address_id=IMMEDIATE, size=2, cycles=2),
    0xE4: OpType(op_code=0xE4, instruction='CPX', address_id=ZEROPAGE, size=2, cycles=3),
    0xEC: OpType(op_code=0xEC, instruction='CPX', address_id=ABSOLUTE, size=3, cycles=4),

    # CPY Compare memory and index Y
    0xC0: OpType(op_code=0xC0, instruction='CPY', address_id=IMMEDIATE, size=2, cycles=2),
    0xC4: OpType(op_code=0xC4, instruction='CPY', address_id=ZEROPAGE, size=2, cycles=3),
    0xCC: OpType(op_code=0xCC, instruction='CPY', address_id=IMMEDIATE, size=3, cycles=4),

    # DEC Decrement memory by one
    0xC6: OpType(op_code=0xC6, instruction='DEC', address_id=ZEROPAGE, size=2, cycles=5),
    0xD6: OpType(op_code=0xD6, instruction='DEC', address_id=ZEROPAGE_X, size=2, cycles=6),
    0xCE: OpType(op_code=0xCE, instruction='DEC', address_id=ZEROPAGE_X, size=3, cycles=6),
    0xDE: OpType(op_code=0xDE, instruction='DEC', address_id=ZEROPAGE_X, size=3, cycles=7),

    # DEX Decrement index X by one
    0xCA: OpType(op_code=0xCA, instruction='DEX', address_id=IMPLIED, size=1, cycles=2),

    # DEY Decrement index Y by one
    0x88: OpType(op_code=0x88, instruction='DEY', address_id=IMPLIED, size=1, cycles=2),

    # EOR "Exclusive-Or" memory with ACCUMULATOR
    0x49: OpType(op_code=0x49, instruction='EOR', address_id=IMMEDIATE, size=2, cycles=2),
    0x45: OpType(op_code=0x45, instruction='EOR', address_id=ZEROPAGE, size=2, cycles=3),
    0x55: OpType(op_code=0x55, instruction='EOR', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x4D: OpType(op_code=0x4D, instruction='EOR', address_id=ABSOLUTE, size=3, cycles=4),
    0x5D: OpType(op_code=0x5D, instruction='EOR', address_id=ABSOLUTE_X, size=3, cycles=4),
    0x59: OpType(op_code=0x59, instruction='EOR', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0x41: OpType(op_code=0x41, instruction='EOR', address_id=INDIRECT_X, size=2, cycles=6),
    0x51: OpType(op_code=0x51, instruction='EOR', address_id=INDIRECT_Y, size=2, cycles=5),

    # INC Increment memory by one
    0xE6: OpType(op_code=0xE6, instruction='INC', address_id=ZEROPAGE, size=2, cycles=5),
    0xF6: OpType(op_code=0xF6, instruction='INC', address_id=ZEROPAGE_X, size=2, cycles=6),
    0xEE: OpType(op_code=0xEE, instruction='INC', address_id=ABSOLUTE, size=3, cycles=6),
    0xFE: OpType(op_code=0xE6, instruction='INC', address_id=ABSOLUTE_X, size=3, cycles=7),

    # INX Increment Index X by one
    0xE8: OpType(op_code=0xE8, instruction='INX', address_id=IMPLIED, size=1, cycles=2),

    # INY Increment Index Y by one
    0xC8: OpType(op_code=0xC8, instruction='INY', address_id=IMPLIED, size=1, cycles=2),

    # JMP Jump to new location
    0x4C: OpType(op_code=0x4C, instruction='JMP', address_id=ABSOLUTE, size=3, cycles=3),
    0x6C: OpType(op_code=0x6C, instruction='JMP', address_id=ABSOLUTE, size=3, cycles=5),

    # JSR Jump to new location saving return address
    0x20: OpType(op_code=0x20, instruction='JSR', address_id=ABSOLUTE, size=3, cycles=6),

    # LDA Load ACCUMULATOR with memory
    0xA9: OpType(op_code=0xA9, instruction='LDA', address_id=IMMEDIATE, size=2, cycles=2),
    0xA5: OpType(op_code=0xA5, instruction='LDA', address_id=ZEROPAGE, size=2, cycles=3),
    0xB5: OpType(op_code=0xB5, instruction='LDA', address_id=ZEROPAGE_X, size=2, cycles=4),
    0xAD: OpType(op_code=0xAD, instruction='LDA', address_id=ABSOLUTE, size=3, cycles=4),
    0xBD: OpType(op_code=0xBD, instruction='LDA', address_id=ABSOLUTE_X, size=3, cycles=4),
    0xB9: OpType(op_code=0xB9, instruction='LDA', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0xA1: OpType(op_code=0xA1, instruction='LDA', address_id=INDIRECT_X, size=2, cycles=6),
    0xB1: OpType(op_code=0xB1, instruction='LDA', address_id=INDIRECT_Y, size=2, cycles=5),

    # LDX Load index X with memory
    0xA2: OpType(op_code=0xA2, instruction='LDX', address_id=IMMEDIATE, size=2, cycles=2),
    0xA6: OpType(op_code=0xA6, instruction='LDX', address_id=ZEROPAGE, size=2, cycles=3),
    0xB6: OpType(op_code=0xB6, instruction='LDX', address_id=ZEROPAGE_Y, size=2, cycles=4),
    0xAE: OpType(op_code=0xAE, instruction='LDX', address_id=ABSOLUTE, size=3, cycles=4),
    0xBE: OpType(op_code=0xBE, instruction='LDX', address_id=IMMEDIATE, size=3, cycles=4),

    # LDY Load index Y with memory 
    0xA0: OpType(op_code=0xA0, instruction='LDY', address_id=IMMEDIATE, size=2, cycles=2),
    0xA4: OpType(op_code=0xA4, instruction='LDY', address_id=ZEROPAGE, size=2, cycles=3),
    0xB4: OpType(op_code=0xB4, instruction='LDY', address_id=ZEROPAGE_X, size=2, cycles=4),
    0xAC: OpType(op_code=0xAC, instruction='LDY', address_id=ABSOLUTE, size=3, cycles=4),
    0xBC: OpType(op_code=0xBC, instruction='LDY', address_id=IMMEDIATE, size=3, cycles=4),

    # LSR Shift right one bit (memory or accumulator)
    0x4A: OpType(op_code=0x4A, instruction='LSR', address_id=ACCUMULATOR, size=1, cycles=2),
    0x46: OpType(op_code=0x46, instruction='LSR', address_id=ZEROPAGE, size=2, cycles=5),
    0x56: OpType(op_code=0x56, instruction='LSR', address_id=ZEROPAGE_X, size=2, cycles=6),
    0x4E: OpType(op_code=0x4E, instruction='LSR', address_id=ABSOLUTE, size=3, cycles=6),
    0x5E: OpType(op_code=0x5E, instruction='LSR', address_id=ABSOLUTE_X, size=3, cycles=7),

    # NOP No operation
    0xEA: OpType(op_code=0xEA, instruction='NOP', address_id=IMPLIED, size=1, cycles=2),

    # ORA "OR" memory with accumulator
    0x09: OpType(op_code=0x09, instruction='ORA', address_id=IMMEDIATE, size=2, cycles=2),
    0x05: OpType(op_code=0x05, instruction='ORA', address_id=ZEROPAGE, size=2, cycles=3),
    0x15: OpType(op_code=0x15, instruction='ORA', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x0D: OpType(op_code=0x0D, instruction='ORA', address_id=ABSOLUTE, size=3, cycles=4),
    0x1D: OpType(op_code=0x1D, instruction='ORA', address_id=ABSOLUTE_X, size=3, cycles=4),
    0x19: OpType(op_code=0x19, instruction='ORA', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0x01: OpType(op_code=0x01, instruction='ORA', address_id=INDIRECT_X, size=2, cycles=6),
    0x11: OpType(op_code=0x11, instruction='ORA', address_id=INDIRECT_Y, size=2, cycles=5),

    # PHA Push accumulator on stack
    0x48: OpType(op_code=0x48, instruction='PHA', address_id=IMPLIED, size=1, cycles=3),

    # PHP Push processor status on stack
    0x08: OpType(op_code=0x08, instruction='PHP', address_id=IMPLIED, size=1, cycles=3),

    # PLA Pull accumulator from stack
    0x68: OpType(op_code=0x68, instruction='PLA', address_id=IMPLIED, size=1, cycles=4),

    # PLP Pull processor status from stack
    0x28: OpType(op_code=0x28, instruction='PLP', address_id=IMPLIED, size=1, cycles=4),

    # ROL Rotate one bit left (memory or accumulator)
    0x2A: OpType(op_code=0x2A, instruction='ROL', address_id=ACCUMULATOR, size=1, cycles=2),
    0x26: OpType(op_code=0x26, instruction='ROL', address_id=ZEROPAGE, size=2, cycles=5),
    0x36: OpType(op_code=0x36, instruction='ROL', address_id=ACCUMULATOR, size=2, cycles=6),
    0x2E: OpType(op_code=0x2E, instruction='ROL', address_id=ACCUMULATOR, size=3, cycles=6),
    0x3E: OpType(op_code=0x3E, instruction='ROL', address_id=ACCUMULATOR, size=3, cycles=7),

    # ROR Rotate one bit right (memory or accumulator)
    0x6A: OpType(op_code=0x6A, instruction='ROR', address_id=ACCUMULATOR, size=1, cycles=2),
    0x66: OpType(op_code=0x66, instruction='ROR', address_id=ZEROPAGE, size=2, cycles=5),
    0x76: OpType(op_code=0x76, instruction='ROR', address_id=ZEROPAGE_X, size=2, cycles=6),
    0x6E: OpType(op_code=0x6E, instruction='ROR', address_id=ABSOLUTE, size=3, cycles=6),
    0x7E: OpType(op_code=0x6A, instruction='ROR', address_id=ABSOLUTE_X, size=3, cycles=7),

    # RTI Return from interrupt
    0x40: OpType(op_code=0x40, instruction='RTI', address_id=IMPLIED, size=1, cycles=6),

    # RTS Return from subroutine
    0x60: OpType(op_code=0x60, instruction='RTS', address_id=IMPLIED, size=1, cycles=6),

    # SBC Subtract memory from accumulator with borrow
    0xE9: OpType(op_code=0xE9, instruction='SBC', address_id=IMMEDIATE, size=2, cycles=2),
    0xE5: OpType(op_code=0xE5, instruction='SBC', address_id=ZEROPAGE, size=2, cycles=3),
    0xF5: OpType(op_code=0xF5, instruction='SBC', address_id=ZEROPAGE_X, size=2, cycles=4),
    0xED: OpType(op_code=0xED, instruction='SBC', address_id=ABSOLUTE, size=3, cycles=4),
    0xFD: OpType(op_code=0xFD, instruction='SBC', address_id=ABSOLUTE_X, size=3, cycles=4),
    0xF9: OpType(op_code=0xF9, instruction='SBC', address_id=ABSOLUTE_Y, size=3, cycles=4),
    0xE1: OpType(op_code=0xE1, instruction='SBC', address_id=INDIRECT_X, size=2, cycles=6),
    0xF1: OpType(op_code=0xF1, instruction='SBC', address_id=INDIRECT_Y, size=2, cycles=5),

    # SEC Set carry flag
    0x38: OpType(op_code=0x38, instruction='SEC', address_id=IMPLIED, size=1, cycles=2),

    # SED Set decimal mode
    0xF8: OpType(op_code=0xF8, instruction='SED', address_id=IMPLIED, size=1, cycles=2),

    # SEI Set interrupt disable status
    0x78: OpType(op_code=0x78, instruction='SEI', address_id=IMPLIED, size=1, cycles=2),

    # STA Store accumulator in memory
    0x85: OpType(op_code=0x85, instruction='STA', address_id=ZEROPAGE, size=2, cycles=3),
    0x95: OpType(op_code=0x95, instruction='STA', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x8D: OpType(op_code=0x8D, instruction='STA', address_id=ABSOLUTE, size=3, cycles=4),
    0x9D: OpType(op_code=0x9D, instruction='STA', address_id=ABSOLUTE_X, size=3, cycles=5),
    0x99: OpType(op_code=0x99, instruction='STA', address_id=ABSOLUTE_Y, size=3, cycles=5),
    0x81: OpType(op_code=0x81, instruction='STA', address_id=INDIRECT_X, size=2, cycles=6),
    0x91: OpType(op_code=0x91, instruction='STA', address_id=INDIRECT_Y, size=2, cycles=6),

    # STX Store index X in memory
    0x86: OpType(op_code=0x86, instruction='STX', address_id=ZEROPAGE, size=2, cycles=3),
    0x96: OpType(op_code=0x96, instruction='STX', address_id=ZEROPAGE_Y, size=2, cycles=4),
    0x8E: OpType(op_code=0x8E, instruction='STX', address_id=ABSOLUTE, size=3, cycles=4),

    # STY Store index Y in memory
    0x84: OpType(op_code=0x84, instruction='STY', address_id=ZEROPAGE, size=2, cycles=3),
    0x94: OpType(op_code=0x94, instruction='STY', address_id=ZEROPAGE_X, size=2, cycles=4),
    0x8C: OpType(op_code=0x8C, instruction='STY', address_id=ABSOLUTE, size=3, cycles=4),

    # TAX Transfer accumulator to index X
    0xAA: OpType(op_code=0xAA, instruction='TAX', address_id=IMPLIED, size=1, cycles=2),

    # TAY Transfer accumulator to index Y
    0xA8: OpType(op_code=0xA8, instruction='TAY', address_id=IMPLIED, size=1, cycles=2),

    # TSX Transfer stack pointer to index 
    0xBA: OpType(op_code=0xBA, instruction='TSX', address_id=IMPLIED, size=1, cycles=2),

    # TXA Transfer index X to accumulator
    0x8A: OpType(op_code=0x8A, instruction='TXA', address_id=IMPLIED, size=1, cycles=2),

    # TXS Transfer index X to stack pointer
    0x9A: OpType(op_code=0x9A, instruction='TXS', address_id=IMPLIED, size=1, cycles=2),

    # TYA Transfer index Y to accumulator
    0x98: OpType(op_code=0x98, instruction='TYA', address_id=IMPLIED, size=1, cycles=2),

}
