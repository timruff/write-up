import subprocess

executable=["/challenge/run"]
for i in range(500):
    executable.append("oxeglyyici")

process = subprocess.Popen(executable, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
error, output = process.communicate()
print(output.decode())
