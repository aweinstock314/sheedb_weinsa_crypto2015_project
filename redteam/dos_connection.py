import subprocess
import time

while True:
	p = subprocess.Popen(["./atm", "8080"], stdin=subprocess.PIPE)
	#p.communicate(input="login Alice")
	p.stdin.write("login Alice\n")
	time.sleep(0.1)
	#p.communicate(input="012345")
	p.stdin.write("012345\n")
	time.sleep(0.1)
	#p.communicate(input="logout")
	p.stdin.write("logout\n")
	time.sleep(0.1)
	p.kill()
