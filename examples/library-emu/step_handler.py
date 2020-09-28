#!/usr/bin/env python

'''
This script is intended to be run on each time a step occurs
in the radare2 ESIL Emulator VM. On each step, obtain the 
current program counter and simulate some behavior depending
on whether there is a hook at the running address.

Note:
Setting cmd.esil.step makes it so the ESIL expressions
are no longer evaluated by the vm, only by the script it is set to.
'''
# Usage: type the below statement into the r2 console
# including quotes
# "e cmd.esil.step=#!pipe python3 step_handler.py"

# Reference: https://github.com/radareorg/radare2-bindings/blob/master/python/test/esil-step/step.py

import sys
import r2pipe

def get_jmp_addr(pipe, pc):
    cmd_response = pipe.cmd("pie 1 @ %s" % pc).rstrip()
    print(cmd_response)
    esil_inputs = cmd_response.split(",")                                                                             
    jmp_index = esil_inputs.index("rip") - 1
    jmp_addr = esil_inputs[jmp_index]
    return jmp_addr

def ptrace_hook(pipe, pc):
    '''
    Log the call to ptrace() and set the return
    value rax to 1
    '''
    print("calling ptrace_hook")
    return_value = 1
    pipe.cmd("dr rax=%d" % return_value)
    sys.exit(return_value)

def jns_hook(pipe, pc):
    '''
    For some reason, the jns true branch isn't
    being taken in the emulation, so we make it
    always take the true branch.

    setting cmd.esil.step makes it so the expressions
    are no longer evaluated by the vm, only by the script
    '''
    print("taking jns_hook")
    jmp_addr = get_jmp_addr(pipe, pc)
    print(f"Taking branch to {jmp_addr}")
    pipe.cmd("aer rip = %s" % jmp_addr)

def jg_hook(pipe, pc):
    print("taking jg_hook")
    jmp_addr = get_jmp_addr(pipe, pc)
    print(f"Taking branch to {jmp_addr}")
    pipe.cmd("aer rip = %s" % jmp_addr)

class StepHandler:

    def __init__(self):
        self.pipe = r2pipe.open()
        self.hooks = {
            0x004006ff: ptrace_hook,
            0x00400707: jns_hook,
            0x00400723: jg_hook,
        }

    def handle_hook(self, pc):
        '''
        Check if current program counter has a hook, then run the hook
        '''
        if pc in self.hooks:
            self.hooks[pc](self.pipe, pc)

    def handle_step(self):
        '''
        On each step, grab the current program counter and print it along
        with the current instruction
        '''
        cmd_response = self.pipe.cmd("dr?PC").rstrip()
        pc = int(cmd_response, 16)
        current_instruction = self.pipe.cmd("pd 1 @ %s" % pc)
        print(hex(pc), current_instruction)

        self.handle_hook(pc)

def main():
    handler = StepHandler()
    handler.handle_step()
    sys.exit(0)

if __name__ == "__main__":
    main()
