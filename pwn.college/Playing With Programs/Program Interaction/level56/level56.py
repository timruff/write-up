import subprocess
parent = subprocess.Popen(["/challenge/run"],stdout=subprocess.PIPE)
child = subprocess.Popen(["/usr/bin/sed","s/ / /"],stdin=parent.stdout,stdout=subprocess.PIPE)
output = child.communicate()[0]
