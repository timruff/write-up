from pwn import *
import subprocess
import os
os.mkfifo('/tmp/myfifo')
fd0 = os.open("/tmp/myfifo",os.O_RDONLY|os.O_NONBLOCK)
fd1 = os.open("/tmp/myfifo",os.O_WRONLY|os.O_NONBLOCK)
fd2=232
os.dup2(fd0,fd2)

binary = "/challenge/run"
p = process([binary],stdin=fd2,close_fds=False)
os.write(fd1,b'lgignqgq')
os.close(fd0)
os.close(fd1)
os.close(fd2)
p.interactive(0)
os.remove('/tmp/myfifo')
