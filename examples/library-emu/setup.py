#!/usr/bin/env python
import r2pipe

r = r2pipe.open()
r.cmd('aa')
#r.cmd('e asm.emu=true')
#r.cmd('e asm.emustr=true')

r.cmd('s main')
r.cmd('aei')
r.cmd('aeim')
r.cmd('aeip')
