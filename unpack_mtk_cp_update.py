#!/usr/bin/env python3

import filetype
import struct
import lzma
import csv
import os
import sys
import lz4.frame

from io import BytesIO
from os import stat

import tarfile
from tarfile import TarFile

MAGIC = 0x58881688
MAGIC2 = 0x58891689

DBG_INFO_NAME = "md1_dbginfo"
MAIN_IMG_NAME = "md1rom"

class MTKSection:
    def __init__(self, loader, name, length, maddr, mode, header_start, data_start):
        self.loader = loader
        self.name = name
        self.length = length
        self.maddr = maddr
        self.mode = mode
        self.header_start = header_start
        self.data_start = data_start

    @property
    def data(self):
        with open(self.loader.md1img, "rb") as f:
            f.seek(self.data_start)
            data = f.read(self.length)
        return data

    def to_file(self, filename):
        with open(self.loader.md1img, "rb") as f:
            f.seek(self.data_start)
            data = f.read(self.length)
        with open(filename, "wb") as f:
            f.write(data)

    def __repr__(self):
        return f"MTKSection {self.name} with 0x{self.length:x} bytes"


class MTKLoader:
    def __init__(self, infile):
        self.md1img = self.unpack_md1img(infile)
        self.sections = {s.name: s for s in self.iter_section_info()}
        self.symbols = {name: v[0] for name, v in self.parse_debug_info().items()}

    def unpack_md1img(self, infile):
        while True:
            g = filetype.guess(infile)
            if g is not None and g.mime == 'application/x-tar':
                tar = TarFile(infile)
                name = None
                for n in tar.getnames():
                    if 'md1img' in n:
                        name = n
                if name is None:
                    raise Exception('md1img not found!')
                tar.extract(name)
                infile = name

            elif g is None and 'md1img.img' in infile:
                return infile
            else:
                raise Exception(f'Could not handle {infile} of type {g.mime}')

    def _getstr(self, raw):
        out = bytearray()
        while True:
            c = raw.read(1)
            if c == b'\x00':
                break
            out += c
        return out.decode()

    def rom_img_data(self):
        return self.sections[MAIN_IMG_NAME].data

    def parse_debug_info(self):
        debug_compressed = self.sections[DBG_INFO_NAME].data
        decompressor = lzma.LZMADecompressor()
        debug_data = BytesIO(decompressor.decompress(debug_compressed))

        debug_info = {}

        # parse header
        debug_data.seek(0x1c)
        target       = self._getstr(debug_data)
        hwplatform   = self._getstr(debug_data)
        moly_version = self._getstr(debug_data)
        buildtime    = self._getstr(debug_data)

        fn_syms_off   = struct.unpack("<I", debug_data.read(4))[0] + 0x10
        file_syms_off = struct.unpack("<I", debug_data.read(4))[0] + 0x10

        while True:
            name   = self._getstr(debug_data)
            start  = struct.unpack("<I", debug_data.read(4))[0]
            end    = struct.unpack("<I", debug_data.read(4))[0]

            while name in debug_info:
                name = name+"_"
            debug_info[name] = (start, end-start)

            if debug_data.tell() >= file_syms_off:
                break
        return debug_info

    def debug_info_to_csv(self, csvfile):
        '''
        The CSV format follows the polypyus format
        '''
        dbg_info = self.parse_debug_info()
        with open(csvfile, 'w') as file:
            fieldnames = ['name', 'addr', 'size', 'mode','type']
            writer = csv.DictWriter(file, fieldnames=fieldnames, delimiter=' ')

            writer.writeheader()
            for name, addrs in dbg_info.items():
                writer.writerow(
                    {'name': name,
                     'addr': addrs[0],
                     'size': addrs[1],
                     'mode': 'UNKOWN',
                     'type': 'FUNC'
                    })


    def debug_info_from_csv(self, csvfile):
        '''
        The CSV format follows the polypyus format
        '''
        dbg_info = {}
        with open(csvfile, 'r') as file:
            fieldnames = ['name', 'addr', 'size', 'mode','type']
            reader = csv.DictReader(file, delimiter=' ')
            for row in reader:
                dbg_info[row['name']] = ( row['addr'], row['size'] )

        return dbg_info


    def iter_section_info(self):
        off = 0
        file_length = stat(self.md1img).st_size

        with open(self.md1img, "rb") as f:
            while off < file_length:
                f.seek(off)
                header = f.read(0x50)

                # special case for samsung signatures
                if header[:9] == b'SignerVer':
                    return
                contents = struct.unpack("<II32sIIIIIIIIII", header)

                magic = contents[0]
                length = contents[1]
                name = contents[2][
                    : contents[2].find(b"\x00")
                ].decode()  # strip after 0byte
                maddr = contents[3]
                mode = contents[4]
                magic2 = contents[5]
                data_off = contents[6]

                assert (
                    magic == MAGIC and magic2 == MAGIC2
                )  # either EOF, or we did smthg wrong

                yield MTKSection(self, name, length, maddr, mode, off, off + data_off)

                off = off + data_off + length
                if off % 0x10:
                    off = off - off % 0x10 + 0x10


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <CP_A415FXX*.tar.md5>")
        exit(1)

    update_file_path = sys.argv[1]

    if not os.path.isfile(update_file_path):
        print(f"[ERROR] file not found: {update_file_path}")
        exit(1)

    g = filetype.guess(update_file_path)
    if g is None or g.mime != 'application/x-tar':
        print(f"[ERROR] update file does not look like a tar archive. Did you provide the correct type of file?")
        exit(1)
    
    update_dir_path, update_file_name = os.path.split(update_file_path)

    out_dir_path = os.path.join(update_dir_path, update_file_name[:update_file_name.index(".")])
    if os.path.exists(out_dir_path):
        print(f"[ERROR] output directory exists. Please delete: '{out_dir_path}'")
        exit(1)

    tf = tarfile.open(update_file_path)
    tf.extractall(out_dir_path)

    compressed_md1_img_path = os.path.join(out_dir_path, "md1img.img.lz4")
    md1img_path = os.path.join(out_dir_path, "md1img.img")

    with lz4.frame.open(compressed_md1_img_path, 'rb') as fp:
        uncompressed_md1img_data = fp.read()
    with open(md1img_path, "wb") as f:
        f.write(uncompressed_md1img_data)

    loader = MTKLoader(md1img_path)

    # Extract sections into output directory
    for secname, sec in loader.sections.items():
        print(f"Extracting file '{secname}'")
        sec.to_file(os.path.join(out_dir_path, secname))

    # Convert debug file into CSV format (for Ghidra consumption)
    loader.debug_info_to_csv(os.path.join(out_dir_path, "md1_dbginfo.csv"))

    # Remove redundant files
    os.remove(compressed_md1_img_path)
    os.remove(md1img_path)

    print(f"Find output files in: {out_dir_path}")
