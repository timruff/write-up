#!/bin/env python
from pwn import *
import subprocess
import os
import fcntl
os.mkfifo('/tmp/myfifo')
os.mkfifo('/tmp/myfifo1')
fd0 = os.open("/tmp/myfifo",os.O_RDONLY|os.O_NONBLOCK)
fd10 = os.open("/tmp/myfifo1",os.O_RDONLY|os.O_NONBLOCK)
fd01 = os.open("/tmp/myfifo",os.O_WRONLY|os.O_NONBLOCK)
fd1 = os.open("/tmp/myfifo1",os.O_WRONLY|os.O_NONBLOCK)
oldfl = fcntl.fcntl(fd0, fcntl.F_GETFL)
fcntl.fcntl(fd0, fcntl.F_SETFL, oldfl & ~os.O_NONBLOCK)

bin1 = "/challenge/run"
p = process([bin1],stdout=fd1,stdin=fd0)
time.sleep(1)
todo = os.read(fd10,4096).decode()
print(todo)
os.write(fd01,b"zvmjetrc")
os.close(fd01)
time.sleep(2)
os.close(fd1)
os.close(fd0)
print(os.read(fd10,4096).decode())
os.close(fd10)
os.remove("/tmp/myfifo")
os.remove("/tmp/myfifo1")
