import subprocess
parent = subprocess.Popen(["/challenge/run"],stdout=subprocess.PIPE)
child = subprocess.Popen(["/usr/bin/rev"],stdin=parent.stdout,stdout=subprocess.PIPE)
output = child.communicate()[0]
