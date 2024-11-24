import subprocess
parent = subprocess.Popen(["/challenge/run"],stdout=subprocess.PIPE)
child = subprocess.Popen(["/usr/bin/grep","pwn"],stdin=parent.stdout,stdout=subprocess.PIPE)
output = child.communicate()[0]
