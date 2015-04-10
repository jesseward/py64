import unittest

from StringIO import StringIO

from py64.loaders.prg import Loader


class PrgTest(unittest.TestCase):

    def setUp(self):
        file_bytes = StringIO(
            '\x01\x08\x0f\x08\xcf\x07\x9e\x32\x30\x36\x35\x20\x41\x42\x43\x00'
        )
        self.file_name = 'TestFileName.PRG'
        self.loader = Loader()
        self.loader.parse(file_bytes, self.file_name)

    def test_prg_start_addr(self):
        """ Is the starting address correctly read. """
        self.assertTrue(self.loader.start_addr == 2049)

    def test_prg_end_addr(self):
        """ Is the end address correctly read. """
        self.assertTrue(self.loader.end_addr == 2064)

    def test_prg_size(self):
        """ Is the program size correctly identified. """
        self.assertTrue(self.loader.size == 16)

    def test_file_type(self):
        """ Is the file of type=prg. """
        self.assertTrue(self.loader.FILE_TYPE == 0x82)

    def test_prg_header_loader(self):
        """ Verifiy header data. """
        header = self.loader.load_header()
        self.assertTrue(header.start_addr == 2049)
        self.assertTrue(header.end_addr == 2064)
        self.assertTrue(header.reserved_a == 0)
        self.assertTrue(header.tape_pos == 0)
        self.assertTrue(header.file_name == self.file_name)

if __name__ == '__main__':
    unittest.main()
