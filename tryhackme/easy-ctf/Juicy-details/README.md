# Juicy Details #

## Task 1 Introduction ##

**Are you ready?**

Il faut télécharger le fichier.   

Réponse : I am ready!    

## Task 2 Reconnaissance ##


**What tools did the attacker use? (Order by the occurrence in the log)**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ ls
access.log  auth.log  vsftpd.log
```

On voit dans access.log.   

```text
::ffff:192.168.10.5 - - [11/Apr/2021:09:08:34 +0000] "POST / HTTP/1.1" 200 1924 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:27 +0000] "GET /rest/user/login HTTP/1.0" 500 - "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:29:15 +0000] "GET /rest/products/search?q=1 HTTP/1.1" 200 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:32:51 +0000] "GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /api HTTP/1.1" 500 - "-" "feroxbuster/2.2.1"
```

En regardant avec un éditeur dans les logs on trouve les outils qui ont permis l'attaque.   

Réponse : nmap, hydra, sqlmap, curl, feroxbuster

**What endpoint was vulnerable to a brute-force attack?**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log | grep login | grep 200
::ffff:192.168.10.5 - - [11/Apr/2021:09:15:03 +0000] "POST /rest/user/login HTTP/1.1" 200 857 "http://192.168.10.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
::ffff:192.168.10.5 - - [11/Apr/2021:09:20:43 +0000] "POST /rest/user/login HTTP/1.1" 200 831 "http://192.168.10.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /login HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
```

\/rest\∕user\/login\/ a été brute forcé avec hydra.   

Réponse : \/rest\∕user\/login\/     

**What endpoint was vulnerable to SQL injection?**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log | grep sql | grep -F "/rest" | grep 200 | head -1
::ffff:192.168.10.5 - - [11/Apr/2021:09:29:14 +0000] "GET /rest/products/search?q=1 HTTP/1.1" 200 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
```

On voit que l'injection est sur \/rest\/products\/search.    

Réponse : \/rest\/products\/search    

**What parameter was used for the SQL injection?**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log | grep sql | grep -F "/rest" | grep 200 | head -1
::ffff:192.168.10.5 - - [11/Apr/2021:09:29:14 +0000] "GET /rest/products/search?q=1 HTTP/1.1" 200 - "-" "sqlmap/1.5.2#stable (http://sqlmap.org)"
```

On voit bien que la paramètre q a été mis.   

Réponse : q

**What endpoint did the attacker try to use to retrieve files? (Include the /)**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log | grep feroxbuster | grep 200
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /a54372a1404141fe8842ae5c029a00e3 HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /3e72ead66df04ca5bff7c9b741883cfbd3044c03e5114f7589804da12c36e5bafa6807b272cf4288ae1316f157b1fab2 HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /administartion HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /login HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /admin HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /backup HTTP/1.1" 200 1924 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /promotion HTTP/1.1" 200 6586 "-" "feroxbuster/2.2.1"
::ffff:192.168.10.5 - - [11/Apr/2021:09:34:33 +0000] "GET /ftp HTTP/1.1" 200 4852 "-" "feroxbuster/2.2.1"
```

Ici ftp est un protocole pour transferer des fichiers.    

Réponse : \/ftp  

## Task 3 Stolen data ##

**What section of the website did the attacker use to scrape user email addresses?**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log | grep 'reviews' | grep 200 | head -10
::ffff:192.168.10.5 - - [11/Apr/2021:09:09:23 +0000] "GET /rest/products/1/reviews HTTP/1.1" 200 172 "http://192.168.10.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```

D'après l'astuce il recommande un endroit où les gens mettent des commentaires.   

La réponse est : products reviews  

**Was their brute-force attack successful? If so, what is the timestamp of the successful login? (Yay/Nay, 11/Apr/2021:09:xx:xx +0000)**  

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat access.log  | grep -i hydra | grep 200
::ffff:192.168.10.5 - - [11/Apr/2021:09:16:31 +0000] "POST /rest/user/login HTTP/1.0" 200 831 "-" "Mozilla/5.0 (Hydra)"
```

On voit que l'attaque a réussie à le 11 Avril 2021 à 09:16:31.     

La réponse est : Yay, 11/Apr/2021:09:16:31 +0000   

**What user information was the attacker able to retrieve from the endpoint vulnerable to SQL injection?**

```bash
::ffff:192.168.10.5 - - [11/Apr/2021:09:32:51 +0000] "GET /rest/products/search?q=qwert%27))%20UNION%20SELECT%20id,%20email,%20password,%20%274%27,%20%275%27,%20%276%27,%20%277%27,%20%278%27,%20%279%27%20FROM%20Users-- HTTP/1.1" 200 3742 "-" "curl/7.74.0"
```

On voit ici que c'est l'email et le mot de passe.   

Réponse : email, password    

**What files did they try to download from the vulnerable endpoint? (endpoint from the previous task, question #5)**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat vsftpd.log | grep DOWNLOAD
Sun Apr 11 09:35:45 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/www-data.bak", 2602 bytes, 544.81Kbyte/sec
Sun Apr 11 09:36:08 2021 [pid 8154] [ftp] OK DOWNLOAD: Client "::ffff:192.168.10.5", "/coupons_2013.md.bak", 131 bytes, 3.01Kbyte/sec
```

On voit ici que deux fichiers ont été téléchargés.   

La réponse est : coupons_2013.md.bak, www-data.bak    

**What service and account name were used to retrieve files from the previous question? (service, username)**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat vsftpd.log | grep 'OK LOGIN' | head -1
Sun Apr 11 08:15:58 2021 [pid 6526] [ftp] OK LOGIN: Client "::ffff:127.0.0.1", anon password "?"
```

Le service est ftp.   

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat vsftpd.log | grep 'LOGIN' | head -1
Sun Apr 11 08:13:40 2021 [pid 6334] [anonymous] FAIL LOGIN: Client "::ffff:127.0.0.1"
```

Le non d'utilisateur est : anonymous.     

La réponse est : ftp, anonymous  

**What service and username were used to gain shell access to the server? (service, username)**

```bash
tim@kali:~/Bureau/tryhackme/write-up/logs$ cat auth.log |grep Accept
Apr 11 09:41:19 thunt sshd[8260]: Accepted password for www-data from 192.168.10.5 port 40112 ssh2
Apr 11 09:41:32 thunt sshd[8494]: Accepted password for www-data from 192.168.10.5 port 40114 ssh2
```

On voit ci dessus que le servie est ssh et que le nom d'utilisateur est www-data.   

Réponse : ssh, www-data  