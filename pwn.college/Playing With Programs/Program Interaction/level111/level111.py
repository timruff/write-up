from pwn import *
import subprocess
import os
binary = "/challenge/run"
p = process([binary])
p.interactive(0)
