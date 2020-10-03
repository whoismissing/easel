aa
s entry0
aei
aeim
aeip

# search for all locations of syscall instruction
# and replace with int 0x420
ahe 0x420,$ @@=`/as`

# view updated esil for the syscalls
pie 1 @@=`/as`

# create an alias to the r2pipe command
"$sys_h=#!pipe python3 syscall_handler.py"

# add r2pipe script alias to a macro
(handle; $sys_h)

# add the macro as the handler to execute on esil interrupts
"e cmd.esil.intr=` `;.(handle)"
