# Crack The Hash Level 2 #

## Task 1 Info Introduction ##

# Task 2 Walkthrough Hash identification #

** Launch Haiti on this hash: **

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti 741ebf5166b9ece4cca88a3868c44871e8370707cf19af3ceaa4a6fba006f224ae03f39153492853
RIPEMD-320 [JtR: dynamic_150]
Umbraco HMAC-SHA1 [HC: 24800]
```

Réponse : RIPEMD-320 

**Launch Haiti on this hash:**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti 1aec7a56aa08b25b596057e1ccbcb6d768b770eaa0f355ccbd56aee5040e02ee
SHA-256 [HC: 1400] [JtR: raw-sha256]
GOST R 34.11-94 [HC: 6900] [JtR: gost]
SHA3-256 [HC: 17400] [JtR: dynamic_380]
Keccak-256 [HC: 17800] [JtR: raw-keccak-256]
Snefru-256 [JtR: snefru-256]
RIPEMD-256 [JtR: dynamic_140]
Haval-256 (3 rounds) [JtR: haval-256-3]
Haval-256 (4 rounds) [JtR: dynamic_290]
Haval-256 (5 rounds) [JtR: dynamic_300]
GOST CryptoPro S-Box
Skein-256 [JtR: skein-256]
Skein-512(256)
PANAMA [JtR: dynamic_320]
BLAKE2-256
MD6-256
Umbraco HMAC-SHA1 [HC: 24800]
```

**What is Keccak-256 Hashcat code?**

Réponse 17800

**What is Keccak-256 John the Ripper code?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ john --list=formats | grep -i keccak
Raw-Keccak, Raw-Keccak-256, Raw-MD4, Raw-MD5, Raw-MD5u, Raw-SHA1, 
```

La réponse est : Raw-Keccak-256  

# Task 3 Walkthrough Wordlists #

**Which option do you need to add to the previous command to search into local archives instead of remote ones?**

Réponse -l   

** path of rockyou **

Réponse : /usr/share/wordlists/passwords/rockyou.txt

Sur kaly linux c'est pas le même chemin, il faudrait installer arch linux.   

** What is the name of the first wordlist in the usernames category? **

```bash
[tim@tim-virtualbox]-[~]
>>> wordlistctl list -g usernames
--==[ wordlistctl by blackarch.org ]==--

[+] available wordlists:

   0 > CommonAdminBase64 (1.05 Kb)
   1 > multiplesources-users-fabian-fingerle (164.59 Kb)
   2 > familynames-usa-top1000 (7.12 Kb)
```

La réponse est : CommonAdminBase64 

# Task 4 Walkthrough Cracking tools, modes & rules #

**What was the password?**

```bash
>>> john hash.txt --format=raw-sha1 --wordlist=/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt --rules=THM01
Created directory: /home/tim/.john
[tim-virtualbox:01147] [[58092,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 AVX 4x])
Press 'q' or Ctrl-C to abort, almost any other key for status
moonligh56       (?)
1g 0:00:00:00 DONE (2021-09-14 11:56) 11.11g/s 6281Kp/s 6281Kc/s 6281KC/s hotrats56..modena56
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

La réponse est : moonligh56

# Task 5 Walkthrough Custom wordlist generation #

```bash
>>> echo 'ed91365105bba79fdab20c376d83d752' > hash.txt 
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> john hash.txt --format=raw-md5 -w=/home/tim/Documents/write-up/dict1.txt
[tim-virtualbox:05656] [[61583,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
mOlo$$u$         (?)
1g 0:00:00:00 DONE (2021-09-14 12:52) 16.66g/s 3200p/s 3200c/s 3200C/s aDvanced..$Hiz
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

La réponse est : mOlo$$u$ 

**What is the last word of the list?**

```bash
>>> cewl -d 2 -w $(pwd)/example.txt https://example.org
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

>>> tail -1 example.txt 
information

```

Le dernier mot de la liste est : information  

**Crack this md5 hash with combination.txt.**

```bash
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> echo 'e5b47b7e8df2597077e703c76ee86aee' > hash.txt 
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> john hash.txt --format=raw-md5 -w=/home/tim/Documents/write-up/combination.txt 
[tim-virtualbox:05799] [[61488,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
1551-li          (?)
1g 0:00:00:01 DONE (2021-09-14 13:00) 0.8000g/s 22679Kp/s 22679Kc/s 22679KC/s 1551-gq..1551-nz
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

La réponse est : 1551-li 

# Challenge It's time to crack hashes #

```bash
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> cat /usr/share/john/john-local.conf 
[List.Rules:THM01]
$[0-9]$[0-9]

[List.Rules:norajCommon01]
c$[0-9]$[0-9]$[$%&*-_+=#@~!]

[List.Rules:norajCommon02]
c$1$2$3$4$[$%&*-_+=#@~!]

[List.Rules:norajCommon03]
r

[List.Rules:norajCommon04]
d
dd
ddd
dddd
```

Le règles de john.  


**Advice n°1 b16f211a8ad7f97778e5006c7cecdf31**

```bash
>>> haiti b16f211a8ad7f97778e5006c7cecdf31
MD5 [HC: 0] [JtR: raw-md5]

>>> echo 'b16f211a8ad7f97778e5006c7cecdf31' > hash.txt 
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> john hash.txt --format=Raw-MD5 -w=/usr/share/wordlists/misc/top_1000_usa_malenames_english.txt --rules=norajCommon02 
[tim-virtualbox:02871] [[60832,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Zachariah1234*   (?)
1g 0:00:00:00 DONE (2021-09-14 13:47) 20.00g/s 80640p/s 80640c/s 80640C/s Valentin1234*..Scott1234+
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

La réponse est : Zachariah1234*  

**Advice n°2 7463fcb720de92803d179e7f83070f97**

```bash
>>> echo '7463fcb720de92803d179e7f83070f97' > hash.txt 
[tim@tim-virtualbox]-[~/Documents/write-up]
>>> john hash.txt --format=raw-md5 --wordlist=/usr/share/wordlists/misc/top_1000_usa_femalenames_english.txt --rules=norajCommon01
[tim-virtualbox:01254] [[57969,0],0] ORTE_ERROR_LOG: Data unpack would read past end of buffer in file util/show_help.c at line 501
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Angelita35!      (?)
1g 0:00:00:00 DONE (2021-09-14 19:51) 7.142g/s 15428Kp/s 15428Kc/s 15428KC/s Annabelle35!..Celina35!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

La réponse est : Angelita35!

**Advice n°3 f4476669333651be5b37ec6d81ef526f**

```bash
>>> echo 'f4476669333651be5b37ec6d81ef526f' > hash.txt 

 tim@kali:~/Bureau/tryhackme/write-up$ hashcat -m0 hash.txt cities.txt -r /usr/share/hashcat/rules/Incisive-leetspeak.rule --quiet
f4476669333651be5b37ec6d81ef526f:Tl@xc@l@ncing0
```
**

Avec le dictionnaire cities.txt et la règele Incisive-leetspeak.rule on trouve le mot de passe.   
La réponse est : Tl@xc@l@ncing0  

**Advice n°4 a3a321e1c246c773177363200a6c0466a5030afc**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 'a3a321e1c246c773177363200a6c0466a5030afc' > hash.txt

tim@kali:~/Bureau/tryhackme/write-up$ cat name.txt 
David Guettapan
david
guettapan
davidguettapan

tim@kali:~/Bureau/tryhackme/write-up$ haiti a3a321e1c246c773177363200a6c0466a5030afc
SHA-1 [HC: 100] [JtR: raw-sha1]

tim@kali:~/Bureau/tryhackme/write-up$ john hash.txt --wordlist=/home/tim/Bureau/tryhackme/write-up/name.txt  --format=raw-sha1  --rules=ALL 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
DavIDgUEtTApAn   (?)
1g 0:00:00:01 DONE (2021-09-15 10:04) 0.8196g/s 27108p/s 27108c/s 27108C/s davID gUeTtaPan..DavIDgUEtTAPAn
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```

Comme on sait que le mot de passe possède un nom et un pénom on fait un dictionnaire.   
On mette toute les règles de john et on trouve la réponse.  

La réponse est : DavIDgUEtTApAn  

** Advice n°5 d5e085772469d544a447bc8250890949 **

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo 'd5e085772469d544a447bc8250890949' > hash.txt 
tim@kali:~/Bureau/tryhackme/write-up$ haiti d5e085772469d544a447bc8250890949
MD5 [HC: 0] [JtR: raw-md5]

tim@kali:~/Bureau/tryhackme/write-up/lyricpass$ python lyricpass.py  -a adele
[+] Looking up artist adele
[+] Found 358 songs for artists adele
[+] All done! 358/358...       

Raw lyrics: raw-lyrics-2021-09-15-10.23.43
Passphrases: wordlist-2021-09-15-10.23.43
tim@kali:~/Bureau/tryhackme/write-up/lyricpass$ cp raw-lyrics-2021-09-15-10.23.43 ../adele.txt
tim@kali:~/Bureau/tryhackme/write-up/lyricpass$ cd ..

tim@kali:~/Bureau/tryhackme/write-up$ john hash.txt --format=raw-md5 --wordlist=adele.txt --rules=norajCommon03 --fork=4
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Node numbers 1-4 of 4 (fork)
uoy ot miws ot em rof peed oot ro ediw oot si revir oN (?)
uoy ot miws ot em rof peed oot ro ediw oot si revir oN (?)
Each node loaded 1/4 of wordfile to memory (about 126 KB/node)
Press 'q' or Ctrl-C to abort, almost any other key for status
4 1g 0:00:00:00 DONE (2021-09-15 10:27) 7.142g/s 2742p/s 2742c/s 2742C/s yawa em welB..revo saw I dna krad saw tI
3 0g 0:00:00:00 DONE (2021-09-15 10:27) 0g/s 25085p/s 25085c/s 25085C/s ,ti tnaem I taht naem t'nod ti ,ti dias I esuac' tsuJ..evol rof neeb t'ndah ti fi ,neeb t'ndah ti fI
2 1g 0:00:00:00 DONE (2021-09-15 10:27) 6.666g/s 2560p/s 2560c/s 2560C/s tnedicca yb enoemos tem I..,traeh ym ,llaf ti tel I
1 0g 0:00:00:00 DONE (2021-09-15 10:27) 0g/s 23400p/s 23400c/s 23400C/s rof uoy gnivael m'I eno eht s'eh ti sah romur tuB..evol rof neeb t'ndah ti fi ,neeb t'ndah ti fI
Waiting for 3 children to terminate
Session completed
```

On télécharge les paroles des chansons d'adele.   
On casse la hash avec le dictionnaire et la règle qui inverse l'ordre des mots.  

La réponse est : uoy ot miws ot em rof peed oot ro ediw oot si revir oN    

**Advice n°6 377081d69d23759c5946a95d1b757adc**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti 377081d69d23759c5946a95d1b757adc
MD5 [HC: 0] [JtR: raw-md5]
tim@kali:~/Bureau/tryhackme/write-up$ echo '377081d69d23759c5946a95d1b757adc' > hash.txt 
```

On prépare le hash.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python pnwgen.py +1721 '' 7 

tim@kali:~/Bureau/tryhackme/write-up$ john hash.txt --format=raw-md5 --wordlist=./wordlist.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
+17215440375     (?)
1g 0:00:00:00 DONE (2021-09-15 10:42) 5.555g/s 30225Kp/s 30225Kc/s 30225KC/s +17215440128..+17215440511
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed

```

On génère le numéros de téléphone avec l'indicatif de saint martin.  
On casse le hash et on trouve la réponse.   

La réponse est : +17215440375 

**Advice n°7 ba6e8f9cd4140ac8b8d2bf96c9acd2fb58c0827d556b78e331d1113fcbfe425ca9299fe917f6015978f7e1644382d1ea45fd581aed6298acde2fa01e7d83cdbd**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti ba6e8f9cd4140ac8b8d2bf96c9acd2fb58c0827d556b78e331d1113fcbfe425ca9299fe917f6015978f7e1644382d1ea45fd581aed6298acde2fa01e7d83cdbd
SHA-512 [HC: 1700] [JtR: raw-sha512]
SHA3-512 [HC: 17600] [JtR: raw-sha3]
SHA3-512 [HC: 17600] [JtR: dynamic_400]

im@kali:~/Bureau/tryhackme/write-up$ echo 'ba6e8f9cd4140ac8b8d2bf96c9acd2fb58c0827d556b78e331d1113fcbfe425ca9299fe917f6015978f7e1644382d1ea45fd581aed6298acde2fa01e7d83cdbd' > hash.txt 

tim@kali:~/Bureau/tryhackme/write-up$ john hash.txt --format=raw-sha3 --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA3 [SHA3 512 32/64])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#redrose!@#    (?)
1g 0:00:00:02 DONE (2021-09-15 10:49) 0.4629g/s 6640Kp/s 6640Kc/s 6640KC/s -xlengx-..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Simplement avec le dictionnaire rockyou on trouve le mot de passe.   
La réponse est : !@#redrose!@#  

**Advice n°8 9f7376709d3fe09b389a27876834a13c6f275ed9a806d4c8df78f0ce1aad8fb343316133e810096e0999eaf1d2bca37c336e1b7726b213e001333d636e896617**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ haiti 9f7376709d3fe09b389a27876834a13c6f275ed9a806d4c8df78f0ce1aad8fb343316133e810096e0999eaf1d2bca37c336e1b7726b213e001333d636e896617
SHA-512 [HC: 1700] [JtR: raw-sha512]
SHA3-512 [HC: 17600] [JtR: raw-sha3]
SHA3-512 [HC: 17600] [JtR: dynamic_400]
Keccak-512 [HC: 18000] [JtR: raw-keccak]
BLAKE2-512 [JtR: raw-blake2]

tim@kali:~/Bureau/tryhackme/write-up$ echo '9f7376709d3fe09b389a27876834a13c6f275ed9a806d4c8df78f0ce1aad8fb343316133e810096e0999eaf1d2bca37c336e1b7726b213e001333d636e896617' > hash.txt 

tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/digininja/CeWL.git
tim@kali:~/Bureau/tryhackme/write-up$ cd CeWL/
tim@kali:~/Bureau/tryhackme/write-up/CeWL$ bundle install --path vendor
tim@kali:~/Bureau/tryhackme/write-up/CeWL$ bundle exec cewl.rb -d 0 -w $(pwd)/rtfm.txt https://rtfm.re/en/sponsors/index.html
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)

tim@kali:~/Bureau/tryhackme/write-up$ john --format=Raw-Blake2 hash.txt --wordlist=./CeWL/rtfm.txt --rules=norajCommon04
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-Blake2 [BLAKE2b 512 128/128 AVX])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hackinghackinghackinghacking (?)
1g 0:00:00:00 DONE (2021-09-15 11:00) 33.33g/s 70000p/s 70000c/s 70000C/s andand..flagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflag
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

On récupère les mots du site rtfm.re.   
Avec les mots de rtfm.re et la régle de répétition on casse le hash.   
Le réponse est : hackinghackinghackinghacking  

**Advice n°9 $6$kI6VJ0a31.SNRsLR$Wk30X8w8iEC2FpasTo0Z5U7wke0TpfbDtSwayrNebqKjYWC4gjKoNEJxO/DkP.YFTLVFirQ5PEh4glQIHuKfA/**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hashcat -h | grep '$6'
   1800 | sha512crypt $6$, SHA512 (Unix)                   | Operating System

tim@kali:~/Bureau/tryhackme/write-up$ echo '$6$kI6VJ0a31.SNRsLR$Wk30X8w8iEC2FpasTo0Z5U7wke0TpfbDtSwayrNebqKjYWC4gjKoNEJxO/DkP.YFTLVFirQ5PEh4glQIHuKfA/' > hash.txt

tim@kali:~/Bureau/tryhackme/write-up$ hashcat -m 1800 -a 0 hash.txt  /usr/share/wordlists/rockyou.txt --quiet
$6$kI6VJ0a31.SNRsLR$Wk30X8w8iEC2FpasTo0Z5U7wke0TpfbDtSwayrNebqKjYWC4gjKoNEJxO/DkP.YFTLVFirQ5PEh4glQIHuKfA/:kakashi1
```

On identifit le hash.    
La crack le hash.   
La réponse est : kakashi1   