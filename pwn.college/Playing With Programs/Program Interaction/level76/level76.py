import subprocess

executable=["env"]
executable.append("-i")
executable.append("231=pqoiuqzdkp")
executable.append("/challenge/run")

process = subprocess.Popen(executable, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
error, output = process.communicate()
print(output.decode())
