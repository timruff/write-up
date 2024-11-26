import subprocess

executable=["env"]
executable.append("-i")
executable.append("22=dnvedcjrnh")
executable.append("/challenge/run")
for i in range(333):
    executable.append("nqhergldgq")

process = subprocess.Popen(executable, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
error, output = process.communicate()
print(output.decode())
