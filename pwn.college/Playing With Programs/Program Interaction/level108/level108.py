import os
# make FIFO
fifo_path = '/tmp/myfifo'
os.mkfifo(fifo_path)
# open FIFO
fd_read = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
fd_write = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
# Duplicate fd
os.dup2(fd_write, 142)

# make child processus
pid = os.fork()
if pid == 0:
    os.execvp('/challenge/run', ['/challenge/run'])
else:
    os.close(fd_read)
    os.close(fd_write)
    os.waitpid(pid, 0)
os.remove(fifo_path)
