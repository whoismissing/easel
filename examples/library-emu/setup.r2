"e cmd.esil.step=#!pipe python3 step_external_calls.py"
aa
s main
aei
aeim
aeip
(ptrace_hook; ?e call ptrace; aepc=[esp]; ae 1,rax,=)
aep .(ptrace_hook) @ 0x004006ff
