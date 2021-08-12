# Memory Forensics #

## Task 1 Introduction ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker pull cincan/volatility
Using default tag: latest
latest: Pulling from cincan/volatility
9b794450f7b6: Pull complete 
ab24643abe07: Pull complete 
6387f17be128: Pull complete 
8933255c9cb9: Pull complete 
48811d32758a: Pull complete 
Digest: sha256:eb9147892fd9b4f638348df0d23a42702978b51022d88c1f3dd1cd5e59cb382a
Status: Downloaded newer image for cincan/volatility:latest
docker.io/cincan/volatility:latest
```

On va utiliser volatily dans docker celui de github fonctionne pas bien.    


## Task 2 Login ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility imageinfo -f Snapshot6.vmem
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/appuser/Snapshot6.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c4a0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c4bd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-27 06:20:05 UTC+0000
     Image local date and time : 2020-12-26 22:20:05 -0800
```

On voit ici que le système d'exploitation est : Win7SP1x64  

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility -f Snapshot6.vmem --profile Win7SP1x64 hashdump --output-file=snapshot6.creds
Volatility Foundation Volatility Framework 2.6.1
Outputting to: snapshot6.creds
tim@kali:~/Bureau/tryhackme/write-up$ cat snapshot6.creds 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John:1001:aad3b435b51404eeaad3b435b51404ee:47fbd6536d7868c873d5ea455f2fc0c9:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:91c34c06b7988e216c3bfeb9530cabfb:::
```

On extrait les hashs.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ john snapshot6.creds -w=/usr/share/wordlists/rockyou.txt --format=NT
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
                 (Administrator)
charmander999    (John)
2g 0:00:00:00 DONE (2021-08-12 15:07) 2.777g/s 19921Kp/s 19921Kc/s 32679KC/s  _ 09..*7¡Vamos!
Warning: passwords printed above might not be all those cracked
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed
```

On crack les hashs avec john the ripper.   

La réponse est: charmander999    

## Task 3 Analysis ##

**When was the machine last shutdown?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility -f Snapshot19.vmem shutdowntime --profile Win7SP1x64
Volatility Foundation Volatility Framework 2.6.1
Registry: SYSTEM
Key Path: ControlSet001\Control\Windows
Key Last updated: 2020-12-27 22:50:12 UTC+0000
Value Name: ShutdownTime
Value: 2020-12-27 22:50:12 UTC+0000
```

On voit que la machine a été éteinte le 27-12-2020 à 22:50:12.    

La réponse est : 2020-12-27 22:50:12    

**What did John write?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility -f Snapshot19.vmem consoles  --profile Win7SP1x64
Volatility Foundation Volatility Framework 2.6.1
**************************************************
ConsoleProcess: conhost.exe Pid: 2488
Console: 0xffa66200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\System32\cmd.exe
Title: Administrator: C:\Windows\System32\cmd.exe
AttachedProcess: cmd.exe Pid: 1920 Handle: 0x60
----
CommandHistory: 0x21e9c0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 7 LastAdded: 6 LastDisplayed: 6
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 at 0x1fe3a0: cd /
Cmd #1 at 0x1f78b0: echo THM{You_found_me} > test.txt
Cmd #2 at 0x21dcf0: cls
Cmd #3 at 0x1fe3c0: cd /Users
Cmd #4 at 0x1fe3e0: cd /John
Cmd #5 at 0x21db30: dir
Cmd #6 at 0x1fe400: cd John
----
Screen 0x200f70 X:80 Y:300
Dump:
                                                                                
C:\>cd /Users                                                                   
                                                                                
C:\Users>cd /John                                                               
The system cannot find the path specified.                                      
                                                                                
C:\Users>dir                                                                    
 Volume in drive C has no label.                                                
 Volume Serial Number is 1602-421F                                              
                                                                                
 Directory of C:\Users                                                          
                                                                                
12/27/2020  02:20 AM    <DIR>          .                                        
12/27/2020  02:20 AM    <DIR>          ..                                       
12/27/2020  02:21 AM    <DIR>          John                                     
04/12/2011  08:45 AM    <DIR>          Public                                   
               0 File(s)              0 bytes                                   
               4 Dir(s)  54,565,433,344 bytes free                              
                                                                                
C:\Users>cd John                                                                
                                                                                
C:\Users\John>                     
```

On voit que john met une phrase dans un fichier grace à la commande : echo THM{You_found_me} > test.txt    

La réponse est : You_found_me     

## Task 4 TrueCrypt ##

** What is the TrueCrypt passphrase? **

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility -f Snapshot14.vmem imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/appuser/Snapshot14.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002c4d0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002c4ed00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-27 13:41:31 UTC+0000
     Image local date and time : 2020-12-27 05:41:31 -0800
```

On remarque que le système d'exploitation est : Win7SP1x64    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up:/home/appuser -ti cincan/volatility -f Snapshot14.vmem truecryptpassphrase --profile Win7SP1x64
Volatility Foundation Volatility Framework 2.6.1
Found at 0xfffff8800512bee4 length 11: forgetmenot
```

On trouve le mot de passe.

La réponse est : forgetmenot  