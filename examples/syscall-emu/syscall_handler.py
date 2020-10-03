#!/usr/bin/env python
import json
import os
import r2pipe
import sys

# Usage: type the below statement into the r2 console
# including quotes
# "e cmd.esil.intr=#!pipe python3 syscall_handler.py"

# Reference: https://radareorg.github.io/blog/posts/emulating-simple-bootloader/

def syscall_exit(pipe):
    regs = json.loads(pipe.cmd("arj"))
    rdi = regs["rdi"] # error_code
    print("[SYSCALL EXIT] %d" % rdi)

def syscall_write(pipe):
    regs = json.loads(pipe.cmd("arj"))
    rdi = regs["rdi"] # fd
    rsi = regs["rsi"] # buf
    rdx = regs["rdx"] # count
    msg = pipe.cmd("psz %d @ %d" % (rdx, rsi))
    print("[SYSCALL WRITE] ==> %s" % msg)


class SyscallHandler:

    def __init__(self):
        self.pipe = r2pipe.open()
        self.syscalls = {
            1: syscall_write, 
            60: syscall_exit
        }

    def handle_syscall(self, code):
        if code in self.syscalls:
            self.syscalls[code](self.pipe)
        else:
            print("[unhandled SYSCALL %d]" % code)

    def handle_interrupt(self):
        regs = json.loads(self.pipe.cmd("arj"))
        rax = regs["rax"]
        self.handle_syscall(rax)

def main():
    handler = SyscallHandler()
    handler.handle_interrupt()

if __name__ == "__main__":
    main()

