import subprocess
p = subprocess.run("cxvwut",text=True)
print(p.stdout)
print(p.stderr)
