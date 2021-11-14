# Forensics #

## Task 1 Volatility forensics ##

**Download the victim.zip**

**What is the Operating System of this Dump file? (OS name)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ unzip victim.zip 
Archive:  victim.zip
  inflating: victim.raw             

tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility imageinfo -f victim.raw
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/appuser/victim.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028420a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002843d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-05-02 18:11:45 UTC+0000
     Image local date and time : 2019-05-02 11:11:45 -0700
```

On voit  que le système d'exploitation est : Win7SO1x64 qui est windows.  

La réponse est : windows    

**What is the PID of SearchIndexer?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 pslist | grep SearchIndexer
0xfffffa8003367060 SearchIndexer.         2180    504     11      629      0      0 2019-05-02 18:03:32 UTC+0000                                 
```

On voit que le PID de SearchIndexer est : 2180    

**What is the last directory accessed by the user?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 shellbags | grep -i -A 3 "Access Date" | cut -c 92- | sort -u | tail
2019-04-23 07:08:44 UTC+0000   NI, DIR                   C:\Users\victim\AppData\LocalLow\Mozilla
2019-04-23 07:26:08 UTC+0000   NI, DIR                   Local\Temp\VBE
2019-04-27 10:36:06 UTC+0000   ARC                       C:\Program Files (x86)\Capture\capture_2742019_336.zip
2019-04-27 10:36:06 UTC+0000   DIR                       C:\Program Files (x86)\Capture
2019-04-27 10:38:22 UTC+0000   NI, DIR                   Z:\logs
2019-04-27 10:38:24 UTC+0000   NI, DIR                   Z:\logs\deleted_files
Access Date                    File Attr                 Path
            Access Date                    File Attr                 Unicode Name
 UTC+0000   2019-04-11 13:29:10 UTC+0000   ARC                       Firefox.lnk 
 UTC+0000   2019-04-13 06:00:40 UTC+0000   ARC                       HxD.lnk 
```

On voit que le dernier répertoire accédé est : deleted_files     

## Task 2 Task2 ##

**There are many suspicious open ports; which one is it? (ANSWER format: protocol:port)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 netscan | head
Volatility Foundation Volatility Framework 2.6.1
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x5c201ca0         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c201ca0         UDPv6    :::5005                        *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c49cbb0         UDPv4    0.0.0.0:59471                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv4    0.0.0.0:59472                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv6    :::59472                       *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4ac630         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c4ac630         UDPv6    :::3702                        *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c519b30         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000

```

Le port suspect est le UDP:5005

**Vads tag and execute protection are strong indicators of malicious processes; can you find which they are? (ANSWER format: Pid1;Pid2;Pid3)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 malfind -D . | grep Pid
Process: explorer.exe Pid: 1860 Address: 0x3ee0000
Process: explorer.exe Pid: 1860 Address: 0x3f90000
Process: svchost.exe Pid: 1820 Address: 0x24f0000
Process: svchost.exe Pid: 1820 Address: 0x4d90000
Process: wmpnetwk.exe Pid: 2464 Address: 0x280000
```

Les processes malicieux sont : 1860;1820;2464  

## Task 3 IOC SAGA ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 memdump --pid=1820,1860,2464 --dump-dir ./
Volatility Foundation Volatility Framework 2.6.1
************************************************************************
Writing explorer.exe [  1860] to 1860.dmp
************************************************************************
Writing svchost.exe [  1820] to 1820.dmp
************************************************************************
Writing wmpnetwk.exe [  2464] to 2464.dmp
```

On récupère la mémoire des processus malicieux.   

**'www.go\*\*\*\*.ru' (write full url without any quotation marks)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E 'www\.go....\.ru'
www.google.ru
www.go4win.ru
www.gocaps.ru
www.goporn.ru
```

La réponse est www.goporn.ru      

**'www.i\*\*\*\*.com' (write full url without any quotation marks)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E 'www\.i....\.com'
www.ikaka.com
http://www.iciba.com/search?s=%si
```

La réponse est : www.ikaka.com    

**'www.ic\*\*\*\*\*\*.com'**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E 'www\.ic......\.com'
www.icsalabs.com
```

La réponse est : www.icsalabs.com     

**202.\*\*\*.233.\*\*\* (Write full IP)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E '202\....\.233\....'
202.107.233.211
```

La réponse est : 202.107.233.211

**\*\*\*.200.\*\*.164 (Write full IP)**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E '...\.200\...\.164'
phttp://209.200.12.164/drm/provider_license_v7.php
```

La réponse est : 209.200.12.164    

**209.190.\*\*\*.\*\*\***

```bash
tim@kali:~/Bureau/tryhackme/write-up$ strings 1820.dmp  | grep -E '209\.190\....\....'
`http://209.190.122.186/drm/license-savenow.asp
```

La réponse est : 209.190.122.186    

**What is the unique environmental variable of PID 2464?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo docker run --rm -v /home/tim/Bureau/tryhackme/write-up/:/home/appuser -ti cincan/volatility -f victim.raw --profile=Win7SP1x64 envars --pid=2464,1820,1860  | sort -k 4 
...
 2464 wmpnetwk.exe         0x00000000002c47a0 OANOCACHE                      1
```

OANACACHE est la seule variable d'environnement unique au pid 2464, les autres au 2464 sont en doublons avec les autres pid.   



