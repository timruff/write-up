import subprocess
parent = subprocess.Popen(["/usr/bin/cat"],stdout=subprocess.PIPE)
child = subprocess.Popen(["/challenge/run"],stdin=parent.stdout,stdout=subprocess.PIPE)
output = child.communicate()[0]
