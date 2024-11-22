import subprocess
myoutput=open("/tmp/?????","w")
subprocess.call("/challenge/run",stdout=myoutput)
subprocess.call(["cat","/tmp/?????"])
