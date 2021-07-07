# Crack the hash #

## Introduction ## 
***
Dans ce write-up nous allons apprendre à utiliser des outils pour cracker des hash

## Level 1 ##
***
Hash : **48bb6e862e54f2a795ffc4e541caed4d**

On identifie le Hash avec **hash-identifier**

```bash
tim@kali:~$ hash-identifier | grep -A 5 "HASH:"
48bb6e862e54f2a795ffc4e541caed4d
 HASH: 
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
```

On voit ici que le hash le plus probable est le md5.

Dans l'aide hashcat on recherche le mode du md5.

```bash
hashcat -h | grep -i md5
      0 | MD5                                              | Raw Hash
   5100 | Half MD5                                         | Raw Hash
     10 | md5($pass.$salt)                                 | Raw Hash, Salted and/or Iterated
     20 | md5($salt.$pass)                                 | Raw Hash, Salted and/or Iterated
   3800 | md5($salt.$pass.$salt)                           | Raw Hash, Salted and/or Iterated
   3710 | md5($salt.md5($pass))                            | Raw Hash, Salted and/or Iterated
   4110 | md5($salt.md5($pass.$salt))                      | Raw Hash, Salted and/or Iterated
   4010 | md5($salt.md5($salt.$pass))                      | Raw Hash, Salted and/or Iterated
  21300 | md5($salt.sha1($salt.$pass))                     | Raw Hash, Salted and/or Iterated
     40 | md5($salt.utf16le($pass))                        | Raw Hash, Salted and/or Iterated
   2600 | md5(md5($pass))                                  | Raw Hash, Salted and/or Iterated
   3910 | md5(md5($pass).md5($salt))                       | Raw Hash, Salted and/or Iterated
   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))          | Raw Hash, Salted and/or Iterated
  21200 | md5(sha1($salt).md5($pass))                      | Raw Hash, Salted and/or Iterated
   4300 | md5(strtoupper(md5($pass)))                      | Raw Hash, Salted and/or Iterated
     30 | md5(utf16le($pass).$salt)                        | Raw Hash, Salted and/or Iterated
   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated
   4710 | sha1(md5($pass).$salt)                           | Raw Hash, Salted and/or Iterated
  21100 | sha1(md5($pass.$salt))                           | Raw Hash, Salted and/or Iterated
  18500 | sha1(md5(md5($pass)))                            | Raw Hash, Salted and/or Iterated
  20800 | sha256(md5($pass))                               | Raw Hash, Salted and/or Iterated
     50 | HMAC-MD5 (key = $pass)                           | Raw Hash, Authenticated
     60 | HMAC-MD5 (key = $salt)                           | Raw Hash, Authenticated
  11900 | PBKDF2-HMAC-MD5                                  | Generic KDF
  11400 | SIP digest authentication (MD5)                  | Network Protocols
   5300 | IKE-PSK MD5                                      | Network Protocols
  10200 | CRAM-MD5                                         | Network Protocols
   4800 | iSCSI CHAP authentication, MD5(CHAP)             | Network Protocols
  11100 | PostgreSQL CRAM (MD5)                            | Network Protocols
   6300 | AIX {smd5}                                       | Operating System
  19000 | QNX /etc/shadow (MD5)                            | Operating System
    500 | md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)        | Operating System
   2410 | Cisco-ASA MD5                                    | Operating System
   2400 | Cisco-PIX MD5                                    | Operating System
  16400 | CRAM-MD5 Dovecot                                 | FTP, HTTP, SMTP, LDAP Server
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR)            | FTP, HTTP, SMTP, LDAP Server
   4711 | Huawei sha1(md5($pass).$salt)                    | Enterprise Application Software (EAS)
   9700 | MS Office <= 2003 $0/$1, MD5 + RC4               | Documents
   9710 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #1  | Documents
   9720 | MS Office <= 2003 $0/$1, MD5 + RC4, collider #2  | Documents
  22500 | MultiBit Classic .key (MD5)                      | Password Managers
  Wordlist + Rules | MD5   | hashcat -a 0 -m 0 example0.hash example.dict -r rules/best64.rule
  Brute-Force      | MD5   | hashcat -a 3 -m 0 example0.hash ?a?a?a?a?a?a
  Combinator       | MD5   | hashcat -a 1 -m 0 example0.hash example.dict example.dict


```

On voit ici le bon mode est 0.

On va utiliser l'attaque par dictionnaire pour casser le MD5

```bash
tim@kali:~/Bureau/tryhackme$ hashcat --quiet -a 0 -m 0 48bb6e862e54f2a795ffc4e541caed4d /usr/share/wordlists/rockyou.txt
48bb6e862e54f2a795ffc4e541caed4d:réponse
```

***
Hash : **CBFDAC6008F9CAB4083784CBD1874F76618D2A97**

On va utiliser les mêmes méthodes que ci-dessus.

```bash
hash-identifier
CBFDAC6008F9CAB4083784CBD1874F76618D2A97
Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

On regarde le mode

```bash
Least Possible Hashs:

tim@kali:~$ hashcat -h | grep -i SHA1
    100 | SHA1                                             | Raw Hash
  21300 | md5($salt.sha1($salt.$pass))                     | Raw Hash, Salted and/or Iterated
   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))          | Raw Hash, Salted and/or Iterated
  21200 | md5(sha1($salt).md5($pass))                      | Raw Hash, Salted and/or Iterated
    110 | sha1($pass.$salt)                                | Raw Hash, Salted and/or Iterated
    120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated
   4900 | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated
   4520 | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated
    140 | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated
  19300 | sha1($salt1.$pass.$salt2)                        | Raw Hash, Salted and/or Iterated
  14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated
   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated
   4710 | sha1(md5($pass).$salt)                           | Raw Hash, Salted and/or Iterated
  21100 | sha1(md5($pass.$salt))                           | Raw Hash, Salted and/or Iterated
  18500 | sha1(md5(md5($pass)))                            | Raw Hash, Salted and/or Iterated
   4500 | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated
    130 | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated
    150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated
    160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated
  12000 | PBKDF2-HMAC-SHA1                                 | Generic KDF
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Generic KDF
  20400 | Python passlib pbkdf2-sha1                       | Generic KDF
   5400 | IKE-PSK SHA1                                     | Network Protocols
  23200 | XMPP SCRAM PBKDF2-SHA1                           | Network Protocols
   7300 | IPMI2 RAKP HMAC-SHA1                             | Network Protocols
  22600 | Telegram Desktop App Passcode (PBKDF2-HMAC-SHA1) | Network Protocols
  11200 | MySQL CRAM (SHA1)                                | Network Protocols
   6700 | AIX {ssha1}                                      | Operating System
   8100 | Citrix NetScaler (SHA1)                          | Operating System
  15100 | Juniper/NetBSD sha1crypt                         | Operating System
   4711 | Huawei sha1(md5($pass).$salt)                    | Enterprise Application Software (EAS)
   9800 | MS Office <= 2003 $3/$4, SHA1 + RC4              | Documents
   9810 | MS Office <= 2003 $3, SHA1 + RC4, collider #1    | Documents
   9820 | MS Office <= 2003 $3, SHA1 + RC4, collider #2    | Documents
  15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers
  13300 | AxCrypt in-memory SHA1                           | Archives
  18100 | TOTP (HMAC-SHA1)                                 | One-Time Passwords
```

On lance l'attaque
```bash
tim@kali:~$ hashcat --quiet -m 100 -a 0 CBFDAC6008F9CAB4083784CBD1874F76618D2A97 /usr//share/wordlists/rockyou.txt 
cbfdac6008f9cab4083784cbd1874f76618d2a97:solution
```

***
Hash : **1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032**

Même méthode.
```bash
tim@kali:~$ hash-identifier | grep -A 5 "HASH:"
1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032
 HASH: 
Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
```

```bash
tim@kali:~$ hashcat -h | grep -i sha | grep 256
   1400 | SHA2-256                                         | Raw Hash
  17400 | SHA3-256                                         | Raw Hash
  21400 | sha256(sha256_bin($pass))                        | Raw Hash
   1410 | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated
   1420 | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated
  22300 | sha256($salt.$pass.$salt)                        | Raw Hash, Salted and/or Iterated
   1440 | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated
  20800 | sha256(md5($pass))                               | Raw Hash, Salted and/or Iterated
  20710 | sha256(sha256($pass).$salt)                      | Raw Hash, Salted and/or Iterated
   1430 | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated
   1450 | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated
   1460 | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated
  10900 | PBKDF2-HMAC-SHA256                               | Generic KDF
  20300 | Python passlib pbkdf2-sha256                     | Generic KDF
  22301 | Telegram Mobile App Passcode (SHA256)            | Network Protocols
   6400 | AIX {ssha256}                                    | Operating System
  19100 | QNX /etc/shadow (SHA256)                         | Operating System
  12800 | MS-AzureSync PBKDF2-HMAC-SHA256                  | Operating System
   7400 | sha256crypt $5$, SHA256 (Unix)                   | Operating System
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating System
   5700 | Cisco-IOS type 4 (SHA256)                        | Operating System
   7401 | MySQL $A$ (sha256crypt)                          | Database Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                 | FTP, HTTP, SMTP, LDAP Server
  10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)          | FTP, HTTP, SMTP, LDAP Server
  20600 | Oracle Transportation Management (SHA256)        | Enterprise Application Software (EAS)
  20711 | AuthMe sha256                                    | Enterprise Application Software (EAS)
  22400 | AES Crypt (SHA256)                               | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit                   | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit                  | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit                  | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode       | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode      | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode      | Full-Disk Encryption (FDE)
  18400 | Open Document Format (ODF) 1.2 (SHA-256, AES)    | Documents
  18800 | Blockchain, My Wallet, Second Password (SHA256)  | Password Managers
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256              | Password Managers
  10000 | Django (PBKDF2-SHA256)                           | Framework
```

```bash
tim@kali:~$ hashcat --quiet -m 1400 -a 0 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032 /usr//share/wordlists/rockyou.txt 
1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:solution
```

***
Hash : **$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom**

Ici c'est un peu plus compliqué on remarque $2y$, ce marqueur nous permettra d'identifier le type de hash

```bash
tim@kali:~$ hashcat -h | grep -F '$2*$'
   3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating System
```

On va utiliser john de ripper.
Le hash blowfish est très long casser dans l'astuce on nous dit de filtrer le mots de passes de rockyou à 4 carractères. 

On filtre le fichier rockyou.txt

```bash
tim@kali:~/Documents/write-up$ cat /usr/share/wordlists/rockyou.txt | grep -E "^....$" > 4caracteres.txt
```

On casse le hash avec john the ripper.
```bash
echo '$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom' > hash

tim@kali:~/Documents/write-up$ john hash --wordlist=./4caracteres.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 4096 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bleh             (?)
1g 0:00:00:11 DONE (2021-07-07 14:18) 0.08756g/s 59.89p/s 59.89c/s 59.89C/s solution..mets
Use the "--show" option to display all of the cracked passwords reliably
Session completed

tim@kali:~/Documents/write-up$ john --show hash
?:solution

1 password hash cracked, 0 left

```
***

Hash : 279412f945939ba78ce0758d3fd83daa

Identification avec hash identifier.
```bash
tim@kali:~/Documents/write-up$ hash-identifier | grep -A 10 HASH


279412f945939ba78ce0758d3fd83daa
 HASH: 
 Not Found.
--------------------------------------------------
 HASH: 
 Not Found.
--------------------------------------------------
 HASH: 
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
```

Ici le MD5 ne fonctionne pas donc essayons le MD4.

```bash
tim@kali:~/Documents/write-up$ hashcat -h | grep -i MD4
    900 | MD4                                              | Raw Hash
echo '279412f945939ba78ce0758d3fd83daa' > hash
tim@kali:~/Documents/write-up$ hashcat --quiet -a 0 -m 900 -r /usr/share/hashcat/rules/toggles2.rule hash  /usr/share/wordlists/rockyou.txt 
279412f945939ba78ce0758d3fd83daa:solution
```

***

## LEVEL 2 ##

hash : **F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85**

Identification

```bash
tim@kali:~/Documents/write-up$ hash-identifier | grep HASH: -A 5
F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
 HASH: 
Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:

tim@kali:~/Documents/write-up$ hashcat -h | grep -i sha | grep 256
   1400 | SHA2-256                                         | Raw Hash
  17400 | SHA3-256                                         | Raw Hash
  21400 | sha256(sha256_bin($pass))                        | Raw Hash
   1410 | sha256($pass.$salt)                              | Raw Hash, Salted and/or Iterated
   1420 | sha256($salt.$pass)                              | Raw Hash, Salted and/or Iterated
  22300 | sha256($salt.$pass.$salt)                        | Raw Hash, Salted and/or Iterated
   1440 | sha256($salt.utf16le($pass))                     | Raw Hash, Salted and/or Iterated
  20800 | sha256(md5($pass))                               | Raw Hash, Salted and/or Iterated
  20710 | sha256(sha256($pass).$salt)                      | Raw Hash, Salted and/or Iterated
   1430 | sha256(utf16le($pass).$salt)                     | Raw Hash, Salted and/or Iterated
   1450 | HMAC-SHA256 (key = $pass)                        | Raw Hash, Authenticated
   1460 | HMAC-SHA256 (key = $salt)                        | Raw Hash, Authenticated
  10900 | PBKDF2-HMAC-SHA256                               | Generic KDF
  20300 | Python passlib pbkdf2-sha256                     | Generic KDF
  22301 | Telegram Mobile App Passcode (SHA256)            | Network Protocols
   6400 | AIX {ssha256}                                    | Operating System
  19100 | QNX /etc/shadow (SHA256)                         | Operating System
  12800 | MS-AzureSync PBKDF2-HMAC-SHA256                  | Operating System
   7400 | sha256crypt $5$, SHA256 (Unix)                   | Operating System
   9200 | Cisco-IOS $8$ (PBKDF2-SHA256)                    | Operating System
   5700 | Cisco-IOS type 4 (SHA256)                        | Operating System
   7401 | MySQL $A$ (sha256crypt)                          | Database Server
   1411 | SSHA-256(Base64), LDAP {SSHA256}                 | FTP, HTTP, SMTP, LDAP Server
  10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)          | FTP, HTTP, SMTP, LDAP Server
  20600 | Oracle Transportation Management (SHA256)        | Enterprise Application Software (EAS)
  20711 | AuthMe sha256                                    | Enterprise Application Software (EAS)
  22400 | AES Crypt (SHA256)                               | Full-Disk Encryption (FDE)
  13751 | VeraCrypt SHA256 + XTS 512 bit                   | Full-Disk Encryption (FDE)
  13752 | VeraCrypt SHA256 + XTS 1024 bit                  | Full-Disk Encryption (FDE)
  13753 | VeraCrypt SHA256 + XTS 1536 bit                  | Full-Disk Encryption (FDE)
  13761 | VeraCrypt SHA256 + XTS 512 bit + boot-mode       | Full-Disk Encryption (FDE)
  13762 | VeraCrypt SHA256 + XTS 1024 bit + boot-mode      | Full-Disk Encryption (FDE)
  13763 | VeraCrypt SHA256 + XTS 1536 bit + boot-mode      | Full-Disk Encryption (FDE)
  18400 | Open Document Format (ODF) 1.2 (SHA-256, AES)    | Documents
  18800 | Blockchain, My Wallet, Second Password (SHA256)  | Password Managers
  16300 | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256     | Password Managers
  15600 | Ethereum Wallet, PBKDF2-HMAC-SHA256              | Password Managers
  10000 | Django (PBKDF2-SHA256)                           | Framework
```

Cassage :

```bash
tim@kali:~/Documents/write-up$ hashcat --quiet -a 0 -m 1400 F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85 /usr/share/wordlists/rockyou.txt 
f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:solution
```

***

Hash : **1DFECA0C002AE40B8619ECF94819CC1B**

Identification :

```bash
tim@kali:~/Documents/write-up$ hash-identifier | grep HASH: -A 10
1DFECA0C002AE40B8619ECF94819CC1B
 HASH: 
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
```

Ici MD5 et MD4 ne fonctionne pas donc faisons une recherche pour le NTLM

```bash
tim@kali:~/Documents/write-up$ hashcat -h | grep NTLM
   5500 | NetNTLMv1 / NetNTLMv1+ESS                        | Network Protocols
   5600 | NetNTLMv2                                        | Network Protocols
   1000 | NTLM                                             | Operating System

```

Cassons le :

```bash
tim@kali:~/Documents/write-up$ hashcat --quiet -a 0 -m 1000 1DFECA0C002AE40B8619ECF94819CC1B /usr/share/wordlists/rockyou.txt 
1dfeca0c002ae40b8619ecf94819cc1b:solution
```

***

Hash : **$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.**
Solution : **aReallyHardSalt**
Identification
```bash
tim@kali:~/Documents/write-up$ hashcat -h | grep -F '$6$'
   1800 | sha512crypt $6$, SHA512 (Unix)                   | Operating System
```

Cassons le 
```bash
tim@kali:~/Documents/write-up$ echo  '$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.' > hash
tim@kali:~/Documents/write-up$ john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:05:15 11,78% (ETA: 16:33:14) 0g/s 5917p/s 5917c/s 5917C/s deshawn88..derling
reponse           (?)
1g 0:00:07:51 DONE (2021-07-07 15:56) 0.002120g/s 6006p/s 6006c/s 6006C/s wakablonde..waite2010
Use the "--show" option to display all of the cracked passwords reliably
Session completed

tim@kali:~/Documents/write-up$ john --show hash
?:solution

1 password hash cracked, 0 left
```

***

Hash : **e5d8870e5bdd26602cab8dbe07a942c8669e56d6**
Salt : **tryhackme**

Identification

```bash
tim@kali:~/Documents/write-up$ hashcat -h | grep -i SHA1
    100 | SHA1                                             | Raw Hash
  21300 | md5($salt.sha1($salt.$pass))                     | Raw Hash, Salted and/or Iterated
   4400 | md5(sha1($pass))                                 | Raw Hash, Salted and/or Iterated
  20900 | md5(sha1($pass).md5($pass).sha1($pass))          | Raw Hash, Salted and/or Iterated
  21200 | md5(sha1($salt).md5($pass))                      | Raw Hash, Salted and/or Iterated
    110 | sha1($pass.$salt)                                | Raw Hash, Salted and/or Iterated
    120 | sha1($salt.$pass)                                | Raw Hash, Salted and/or Iterated
   4900 | sha1($salt.$pass.$salt)                          | Raw Hash, Salted and/or Iterated
   4520 | sha1($salt.sha1($pass))                          | Raw Hash, Salted and/or Iterated
    140 | sha1($salt.utf16le($pass))                       | Raw Hash, Salted and/or Iterated
  19300 | sha1($salt1.$pass.$salt2)                        | Raw Hash, Salted and/or Iterated
  14400 | sha1(CX)                                         | Raw Hash, Salted and/or Iterated
   4700 | sha1(md5($pass))                                 | Raw Hash, Salted and/or Iterated
   4710 | sha1(md5($pass).$salt)                           | Raw Hash, Salted and/or Iterated
  21100 | sha1(md5($pass.$salt))                           | Raw Hash, Salted and/or Iterated
  18500 | sha1(md5(md5($pass)))                            | Raw Hash, Salted and/or Iterated
   4500 | sha1(sha1($pass))                                | Raw Hash, Salted and/or Iterated
    130 | sha1(utf16le($pass).$salt)                       | Raw Hash, Salted and/or Iterated
    150 | HMAC-SHA1 (key = $pass)                          | Raw Hash, Authenticated
    160 | HMAC-SHA1 (key = $salt)                          | Raw Hash, Authenticated
  12000 | PBKDF2-HMAC-SHA1                                 | Generic KDF
  12001 | Atlassian (PBKDF2-HMAC-SHA1)                     | Generic KDF
  20400 | Python passlib pbkdf2-sha1                       | Generic KDF
   5400 | IKE-PSK SHA1                                     | Network Protocols
  23200 | XMPP SCRAM PBKDF2-SHA1                           | Network Protocols
   7300 | IPMI2 RAKP HMAC-SHA1                             | Network Protocols
  22600 | Telegram Desktop App Passcode (PBKDF2-HMAC-SHA1) | Network Protocols
  11200 | MySQL CRAM (SHA1)                                | Network Protocols
   6700 | AIX {ssha1}                                      | Operating System
   8100 | Citrix NetScaler (SHA1)                          | Operating System
  15100 | Juniper/NetBSD sha1crypt                         | Operating System
   4711 | Huawei sha1(md5($pass).$salt)                    | Enterprise Application Software (EAS)
   9800 | MS Office <= 2003 $3/$4, SHA1 + RC4              | Documents
   9810 | MS Office <= 2003 $3, SHA1 + RC4, collider #1    | Documents
   9820 | MS Office <= 2003 $3, SHA1 + RC4, collider #2    | Documents
  15500 | JKS Java Key Store Private Keys (SHA1)           | Password Managers
  13300 | AxCrypt in-memory SHA1                           | Archives
  18100 | TOTP (HMAC-SHA1)                                 | One-Time Passwords

```

ça ressemble à du sha1 avec un salage.
Dans l'astuce on dit que c'est du HMAC donc c'est du HMAC-SHA1

Craquons le :

```bash
echo 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' > hash

tim@kali:~/Documents/write-up$ hashcat --quiet -a 0 -m 160 hash /usr/share/wordlists/rockyou.txt 
e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:solution

```