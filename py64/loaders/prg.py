#!/usr/bin/env python2
# I, Danny Milosavljevic, hereby place this file into the public domain.

import sys
import struct
import entries
from entries import Entry
import os

"""
Note: taken from https://hkn.eecs.berkeley.edu/~mcmartin/ophis/manual/x51.html
The PRG format is ludicrously simple. It has two bytes of header data: This is a little-endian number indicating the starting address. The rest of the file is a single continuous chunk of data loaded into memory, starting at that address. BASIC memory starts at memory location 2048, and that's probably where we'll want to start.

Well, not quite. We want our program to be callable from BASIC, so we should have a BASIC program at the start. We guess the size of a simple one line BASIC program to be about 16 bytes. Thus, we start our program at memory location 2064 ($0810), and the BASIC program looks like this:

10 SYS 2064
    
We SAVE this program to a file, then study it in a debugger. It's 15 bytes long:

1070:0100  01 08 0C 08 0A 00 9E 20-32 30 36 34 00 00 00
    
The first two bytes are the memory location: $0801. The rest of the data breaks down as follows:

Table 1. BASIC program breakdown

Memory Locations  Value
$0801-$0802       2-byte pointer to the next line of BASIC code ($080C).
$0803-$0804       2-byte line number ($000A = 10).
$0805             Byte code for the SYS command.
$0806-$080A       The rest of the line, which is just the string " 2064".
$080B             Null byte, terminating the line.
$080C-$080D       2-byte pointer to the next line of BASIC code ($0000 = end of program).

"""


class Loader(entries.Loader):

    FILE_TYPE = 0x82  # prg

    def __init__(self):

        self.start_addr = 0
        self.end_addr = 0
        self.file_name = ""
        self.size = 0
        self.stream = None
        pass

    def parse(self, stream, file_name):
        beginning_pos = int(stream.tell())
        stream.seek(0, 2)
        end_pos = int(stream.tell())
        stream.seek(0)
        self.file_name = file_name
        self.size = end_pos - beginning_pos
        header_format = "<H"
        header_size = struct.calcsize(header_format)
        data = stream.read(header_size)
        assert(len(data) == header_size)
        # FIXME start_addr, = struct.unpack(header_format, data)
        start_addr = ord(data[0]) | (ord(data[1]) << 8)
        self.start_addr = start_addr
        self.end_addr = self.start_addr + end_pos - 1
        self.stream = stream
        return self

    def load_header(self):

        # TODO mangle back to C64 format (16 char filename).
        file_name = os.path.basename(self.file_name)
        print("loading header PRG")
        tape_pos = 0
        return Entry(B_used=True, file_type=self.FILE_TYPE,
                    start_addr=self.start_addr,
                    end_addr=self.end_addr,
                    reserved_a=0,
                    tape_pos=tape_pos,
                    reserved_b=0,
                    file_name = file_name)

    def load_data(self, file_name):
        print('loading data PRG')
        self.stream.seek(0)
        data = self.stream.read(self.end_addr - self.start_addr + 1)
        return data

if __name__ == "__main__":
    import argparse
    import os.path

    parser = argparse.ArgumentParser(description='Read a C64 program file.')
    parser.add_argument('filename', type=str, nargs=1, help=
        'Specify the filename of the C64 file format.')

    args = parser.parse_args()
    filename = args.filename[0]

    if not os.path.isfile(filename):
        sys.exit('Unable to locate {0}',format(filename))

    print(
        Loader().parse(open(filename, 'rb'), 
                       filename).start_addr, filename
        )
