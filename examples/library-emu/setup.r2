aa
s main
aei
aeim
aeip

# create a macro 
#(ptrace_hook; ?e call ptrace; aepc=[esp]; ae 1,rax,=)

# create an alias
"$step_h=#!pipe python3 step_handler.py"

# set the macro to the alias
(handle; $step_h)

# pin the macro
aep .(handle) @ 0x00400570 # ptrace
aep .(handle) @ 0x00400723 # jg
aep .(handle) @ 0x00400677 # xor

#aesu 0x004006c7
#px @ rsp
