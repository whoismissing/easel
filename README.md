# easel

1. What is ESIL?
ESIL stands for 'Evaluable Strings Intermediate Language'. It is a stack based IL where each
ESIL expression represents an individual instruction. Commands are separated by commas and
read from left-to-right in post-fix notation.

2. What does the ESIL virtual machine look like?
Pseudocode for the ESIL VM is generally described as:
```
while word = haveCommand():
    if word.isOperator():
        esilOperators[word](vm)
    else:
        vm.push(word)
    nextCommand()
```

There are two categories of inputs: 
* values - A value gets pushed to the stack
* operators - An operator pops the values (arguments) off the stack, does some work, then pushes the result.

Example ESIL expression (post-fix):
`4,esp,-=,ebp,esp,=[4]`

ESIL expression converted to in-fix:
```
esp -= 4      // raise esp by 4
4 bytes [esp] = ebp   // write the value of ebp [size of dword (4 bytes)] to top of stack 
```

We have `push ebp`!

3. How do we view ESIL expressions in r2?
Display ESIL information
`[0x00000000]> e emu.str = true`

Only view ESIL expressions instead of assembly
`[0x00000000]> e asm.esil = true`

4. What commands can we use with ESIL?
* 'aei': Initialize the ESIL virtual machine

* 'aeim': Initialize the ESIL virtual machine memory (stack)

* 'aeip': Set the initial ESIL virtual machine instruction pointer

* 'aer': Set up initial register values

* 'ae': evaluate an ESIL expression
`ae 1,1,+`

* 'aes': step an ESIL expression

* 'aets+': create a new record and replay mode session for reverse debugging

* 'aesb': step backwards in the reverse debugging session

ESIL memory commands:
* `esil.stack`: enable or disable the stack for asm.emu mode
* `esil.stack.addr`: set the stack address for the ESIL VM
* `esil.stack.size`: set the stack size for the ESIL VM
* `esil.stack.depth`: limit the number of pushes that can be done on the stack
* `esil.romem`: specify read-only access to the ESIL memory
* `esil.fillstack` and `esil.stack.pattern`: fill the ESIL VM stack with a pattern upon initialization
* `esil.nonull`: stop the ESIL VM execution on a NULL pointer read or write

5. What is ESIL used for?
ESIL is used to accomplish partial emulation (imprecise emulation).

The ESIL VM is not expected to emulate external calls, system calls, or SIMD instructions.

ESIL emulation has seen use for:
* calculating indirect jumps and conditional jumps
* encryption / decryption routines 
* unpacking
* deobfuscation (polymorphic / self-writing code)

ESIL is also being experimented with for symbolic execution.

6. How does ESIL compare to other IL's?

TODO: continue this section

Ghidra's Pcode is more verbose

Angr uses VEX IR

Errata:
* [ESIL execution cost](https://github.com/radareorg/radare2/pull/17585)

References:
* [ESIL syntax](https://r2wiki.readthedocs.io/en/latest/home/misc/usage-examples/)
* [ESIL commands](https://radare.gitbooks.io/radare2book/content/disassembling/esil.html)
* [Decryption example](https://blog.superponible.com/2017/04/15/emulating-assembly-in-radare2/)

cool projects:
* [ESILSolve Symbolic Executor](https://github.com/aemmitt-ns/esilsolve) - z3 and ESIL for symbolic execution
* [Modality Symbolic Executor](https://github.com/0xchase/modality) - r2 plugin to integrate symbolic execution capabilities of angr

