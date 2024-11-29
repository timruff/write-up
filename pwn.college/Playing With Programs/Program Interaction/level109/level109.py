from pwn import *
import subprocess
import os
binary = "/challenge/run"
p = process([binary],stdout=sys.stdin)
p.interactive(0)
