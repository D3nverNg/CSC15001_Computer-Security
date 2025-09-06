# bmp.py — pure-Python shim for your solve.py (no external deps)
# Exposes BMPHeader and DIBHeader with .to_bytes() like a tiny header builder.
# Place this file next to solve.py so "from bmp import *" works.

import struct

class BMPHeader:
    def __init__(self, bf_size, bf_type=b'BM', bf_off_bits=54):
        if not isinstance(bf_type, (bytes, bytearray)) or len(bf_type) != 2:
            raise ValueError("bf_type must be 2 bytes, e.g., b'BM'")
        self.bf_type = bytes(bf_type)
        self.bf_size = int(bf_size) & 0xFFFFFFFF
        self.bf_reserved1 = 0
        self.bf_reserved2 = 0
        self.bf_off_bits = int(bf_off_bits) & 0xFFFFFFFF

    def to_bytes(self) -> bytes:
        # BITMAPFILEHEADER (14 bytes)
        return struct.pack(
            '<2sIHHI',
            self.bf_type,
            self.bf_size,
            self.bf_reserved1,
            self.bf_reserved2,
            self.bf_off_bits
        )

class DIBHeader:
    def __init__(
        self,
        bi_width,
        bi_height,
        bi_size_image,
        bi_bit_count=24,
        bi_compression=0,
        bi_xppm=0,
        bi_yppm=0,
        bi_clr_used=0,
        bi_clr_important=0
    ):
        # BITMAPINFOHEADER (40 bytes)
        self.bi_size = 40
        self.bi_width = int(bi_width)
        self.bi_height = int(bi_height)
        self.bi_planes = 1
        self.bi_bit_count = int(bi_bit_count) & 0xFFFF
        self.bi_compression = int(bi_compression) & 0xFFFFFFFF  # 0 = BI_RGB
        self.bi_size_image = int(bi_size_image) & 0xFFFFFFFF
        self.bi_xppm = int(bi_xppm)
        self.bi_yppm = int(bi_yppm)
        self.bi_clr_used = int(bi_clr_used)
        self.bi_clr_important = int(bi_clr_important)

    def to_bytes(self) -> bytes:
        # Pack as <IIIHHIIIIII (40 bytes)
        return struct.pack(
            '<IIIHHIIIIII',
            self.bi_size,
            self.bi_width,
            self.bi_height,
            self.bi_planes,
            self.bi_bit_count,
            self.bi_compression,
            self.bi_size_image,
            self.bi_xppm,
            self.bi_yppm,
            self.bi_clr_used,
            self.bi_clr_important
        )
