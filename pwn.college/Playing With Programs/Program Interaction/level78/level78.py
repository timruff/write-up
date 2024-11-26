import subprocess
executable=[]
myinput=open("gvhrgy")
executable.append("/challenge/run")
process = subprocess.Popen(executable, stdin=myinput)
process.wait()
