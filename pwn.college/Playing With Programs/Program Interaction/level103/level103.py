from pwn import *
import subprocess
import os
os.mkfifo('/tmp/myfifo')
fd0 = os.open("/tmp/myfifo",os.O_RDONLY|os.O_NONBLOCK)
fd1 = os.open("/tmp/myfifo",os.O_WRONLY|os.O_NONBLOCK)

binary = "/challenge/run"
p = process([binary],stdin=fd0)
os.write(fd1,b'acdibxep')
os.close(fd1)
os.close(fd0)
p.interactive(0)
os.remove('/tmp/myfifo')
