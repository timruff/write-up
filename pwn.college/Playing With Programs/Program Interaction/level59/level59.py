import subprocess
p1 = subprocess.Popen(["/usr/bin/rev"],stdout=subprocess.PIPE)
p2 = subprocess.Popen(["/usr/bin/rev"],stdin=p1.stdout,stdout=subprocess.PIPE)
p3 = subprocess.Popen(["/challenge/run"],stdin=p2.stdout,stdout=subprocess.PIPE)
output = p3.communicate()[0]
print(output.decode())
