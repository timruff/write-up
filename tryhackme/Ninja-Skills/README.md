# Ninja Skills #

**Connexion**
```bash
tim@kali:~/Bureau/tryhackme/write-up$ ssh new-user@10.10.135.124
new-user@10.10.135.124's password: 
Last failed login: Fri Jul 16 08:05:40 UTC 2021 from ip-10-9-228-66.eu-west-1.compute.internal on ssh:notty
There was 1 failed login attempt since the last successful login.
Last login: Wed Oct 23 22:13:05 2019 from ip-10-10-231-194.eu-west-1.compute.internal
████████╗██████╗ ██╗   ██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███╗   ███╗███████╗
╚══██╔══╝██╔══██╗╚██╗ ██╔╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝████╗ ████║██╔════╝
   ██║   ██████╔╝ ╚████╔╝ ███████║███████║██║     █████╔╝ ██╔████╔██║█████╗  
   ██║   ██╔══██╗  ╚██╔╝  ██╔══██║██╔══██║██║     ██╔═██╗ ██║╚██╔╝██║██╔══╝  
   ██║   ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗██║ ╚═╝ ██║███████╗
   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
	Let the games begin!
[new-user@ip-10-10-135-124 ~]$ 

```

**Which of the above files are owned by the best-group group(enter the answer separated by spaces in alphabetical order)**

Nous allons chercher les fichiers qui appartient à best-group.  
```bash
[new-user@ip-10-10-135-124 ~]$ find / -group best-group 2>/dev/null
/mnt/D8B3
/home/v2Vb
```

**Which of these files contain an IP address?**
Nous allons chercher un fichier qui contient une adresse ip.  

```bash
[new-user@ip-10-10-135-124 ~]$ find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiMO -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \)  -exec grep -EoH "([0-9]{1,3}[\.]){3}[0-9]{1,3}" '{}' \; 2> /dev/null
/opt/oiMO:1.1.1.1
```

J'utilise find avec les options :
-/ recherche tous les fichiers à partir du répertoire racine.
-L'option type f dit ce que l'on cherche sont des fichiers.
-Ce qui est entre parenthèse permet de trouver les fichiers de l'exercice.
-L'option name pour le définir les noms des fichiers.
-L'option o est un opérateur OU.  
-exec exécute la commande passée.
-{} remplace ceci par le fichier?
-; terminaison de la commande.
-À la fin toutes les erreurs sont dirigés dans /dev/null.

On filtre le résultat avec Grep :
-L'option E on utilise les expressions régulière.
-L'option -o on ne sort que le résultat trouvé.
-L'option -H on affiche le fichier où la chaîne à été trouvée.

L'expression régulière : 
-[0-9] signifie cherche un nombre entre 0 et 9.
-{1,3} signifie répète le recherche sur le motif de précédente de 1 à 3.
-[\.] signifie recher un point.