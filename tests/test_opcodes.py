import unittest

import py64.opcodes as op_code


class OpCodeTest(unittest.TestCase):

    def setUp(self):

        self.opcode = op_code.instruction_set[0x4C]

    def test_instruction_set(self):
        """ Verify integrity of instruction set data. """
        self.assertTrue(self.opcode.instruction == 'JMP')
        self.assertTrue(self.opcode.address_id == op_code.ABSOLUTE)
        self.assertTrue(self.opcode.size == 3)
        self.assertTrue(self.opcode.cycles == 3)

if __name__ == '__main__':
    unittest.main()
