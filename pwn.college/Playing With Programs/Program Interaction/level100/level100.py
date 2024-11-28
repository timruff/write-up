import subprocess
p = subprocess.run("/challenge/run",text=True)
print(p.stdout)
print(p.stderr)
