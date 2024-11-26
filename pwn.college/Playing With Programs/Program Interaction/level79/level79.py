import subprocess

executable=["env"]
executable.append("-C")
executable.append("/tmp/rfdtev")
executable.append("/challenge/run")

process = subprocess.Popen(executable, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
error, output = process.communicate()
print(output.decode())
