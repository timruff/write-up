import subprocess
p = subprocess.run("/tmp/zkmdlw",text=True)
print(p.stdout)
print(p.stderr)
