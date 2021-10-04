# Classic Passwd #

## Task 1 Get the flag ##

**What is the flag?**

On télécharge le fichier.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ltrace ./Challenge.Challenge 
printf("Insert your username: ")                                                                                                                   = 22
__isoc99_scanf(0x55c0b13c901b, 0x7ffdd1cd6690, 0, 0Insert your username: toto 
)                                                                                               = 1
strcpy(0x7ffdd1cd6600, "toto")                                                                                                                     = 0x7ffdd1cd6600
strcmp("toto", "AGB6js5d9dkG7")                                                                                                                    = 51
puts("\nAuthentication Error"
Authentication Error
)                                                                                                                     = 22
exit(0 <no return ...>
+++ exited (status 0) +++
```

On test un mot de passe en traçant le programme, on voit que notre mot de passe est comparé avec le bon qui est : AGB6js5d9dkG7     

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ./Challenge.Challenge 
Insert your username: AGB6js5d9dkG7

Welcome
THM{65235128496}
```

On met le bon mot de passe et on a notre flag.  

La réponse est : THM{65235128496}  