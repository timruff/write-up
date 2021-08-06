# Intro to x86-64 #

## Task 1 Description and Objectives  ##

```bash
tim@kali:~/Bureau/tryhackme/write-up$ sudo sh -c  "echo '10.10.191.174 introx8664.thm' >> /etc/hosts"
[sudo] Mot de passe de tim :     

tim@kali:~/Bureau/tryhackme/write-up$ ssh tryhackme@introx8664.thm
tryhackme@introx8664.thm's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-1035-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Aug  2 06:24:30 UTC 2021

  System load:  0.0               Processes:           87
  Usage of /:   32.1% of 7.69GB   Users logged in:     0
  Memory usage: 29%               IP address for eth0: 10.10.191.174
  Swap usage:   0%


  Get cloud support with Ubuntu Advantage Cloud Guest:
    http://www.ubuntu.com/business/services/cloud

77 packages can be updated.
0 updates are security updates.


Last login: Sat May 11 22:34:17 2019 from 92.233.131.51
```

Réglage du DNS.   
Connexion avec les identifiants :     
Nom : tryhackme   
Mot de passe : reismyfavl33t     

## Task 2 Introduction ##

## Task 3 If Statements ##

## Task 4 If Statements Continued ##

```bash
tryhackme@ip-10-10-191-174:~/if-statement$ r2 -d if2
Process with PID 16087 started...
= attach 16087 16087
bin.baddr 0x55ea48980000
Using 0x55ea48980000
asm.bits 64
 -- Press 'c' in visual mode to toggle the cursor mode
[0x7fddc347e090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7fddc347e090]> afl
0x55ea489804f0    1 42           entry0
0x55ea48b80fe0    1 4124         reloc.__libc_start_main
0x55ea48980520    4 50   -> 40   sym.deregister_tm_clones
0x55ea48980560    4 66   -> 57   sym.register_tm_clones
0x55ea489805b0    5 58   -> 51   entry.fini0
0x55ea489804e0    1 6            sym.imp.__cxa_finalize
0x55ea489805f0    1 10           entry.init0
0x55ea489806b0    1 2            sym.__libc_csu_fini
0x55ea489806b4    1 9            sym._fini
0x55ea48980640    4 101          sym.__libc_csu_init
0x55ea489805fa    5 68           main
0x55ea489804b8    3 23           sym._init
[0x7fddc347e090]> pdf @main
/ (fcn) main 68
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_ch @ rbp-0xc
|           ; var int32_t var_8h @ rbp-0x8
|           ; var int32_t var_4h @ rbp-0x4
|           ; DATA XREF from entry0 (0x55ea4898050d)
|           0x55ea489805fa      55             pushq %rbp
|           0x55ea489805fb      4889e5         movq %rsp, %rbp
|           0x55ea489805fe      c745f4000000.  movl $0, var_ch
|           0x55ea48980605      c745f8630000.  movl $0x63, var_8h      ; 'c' ; 99
|           0x55ea4898060c      c745fce80300.  movl $0x3e8, var_4h     ; 1000
|           0x55ea48980613      8b45f4         movl var_ch, %eax
|           0x55ea48980616      3b45f8         cmpl var_8h, %eax
|       ,=< 0x55ea48980619      7d0e           jge 0x55ea48980629
|       |   0x55ea4898061b      8b45f8         movl var_8h, %eax
|       |   0x55ea4898061e      3b45fc         cmpl var_4h, %eax
|      ,==< 0x55ea48980621      7d0d           jge 0x55ea48980630
|      ||   0x55ea48980623      8365f864       andl $0x64, var_8h
|     ,===< 0x55ea48980627      eb07           jmp 0x55ea48980630
|     ||`-> 0x55ea48980629      8145f4b00400.  addl $0x4b0, var_ch
|     ||    ; CODE XREF from main (0x55ea48980627)
|     ``--> 0x55ea48980630      816dfce70300.  subl $0x3e7, var_4h
|           0x55ea48980637      b800000000     movl $0, %eax
|           0x55ea4898063c      5d             popq %rbp
\           0x55ea4898063d      c3             retq

```

On prépare le binaire.  
Désassemble la fonction main du programme.   

**What is the value of var_8h before the popq and ret instructions?**

```bash
[0x7fddc347e090]> db 0x55ea4898063c

[0x7fddc347e090]> dc
hit breakpoint at: 55ea4898063c

[0x55da0861863c]> pfi @rbp-0x8
0x7fff1dce9cd8 = 96
```

On met un break point sur l'instruction popq.    
On exécute le programme jusqu'au breakpoint.   
On affiche la valeur var_8h en mode entier signé.   


**what is the value of var_ch before the popq and ret instructions?**

```bash
[0x7fddc347e090]> db 0x55ea4898063c

[0x7fddc347e090]> dc
hit breakpoint at: 55ea4898063c

[0x55da0861863c]> pfi @rbp-0xc
0x7fff1dce9cd4 = 0
```

On affiche la valeur var_ch en mode entier signé.   

**What is the value of var_4h before the popq and ret instructions?**

```bash
[0x7fddc347e090]> db 0x55ea4898063c

[0x7fddc347e090]> dc
hit breakpoint at: 55ea4898063c

[0x55da0861863c]> pfi @rbp-0x4
0x7fff1dce9cdc = 1
```
On affiche la valeur var_4h en mode entier signé.   

**What operator is used to change the value of var_8h, input the symbol as your answer\(symbols include +, -, *, \/, &, |\):**

L'opérateur &  est utilisé pour changer la valeur var_8h.   
Réponse  :  &  

## Task 5 Loops ##

```bash
tryhackme@ip-10-10-191-174:~/loops$ r2 -d loop2 
Process with PID 16122 started...
= attach 16122 16122
bin.baddr 0x55f7d18fd000
Using 0x55f7d18fd000
asm.bits 64
 -- **** COMMODORE 64 RADARE V2 ****  64K RAM SYSTEM  38911 DISASM BYTES FREE  READY.
[0x7f9f27960090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f9f27960090]> afl
0x55f7d18fd4f0    1 42           entry0
0x55f7d1afdfe0    1 4124         reloc.__libc_start_main
0x55f7d18fd520    4 50   -> 40   sym.deregister_tm_clones
0x55f7d18fd560    4 66   -> 57   sym.register_tm_clones
0x55f7d18fd5b0    5 58   -> 51   entry.fini0
0x55f7d18fd4e0    1 6            sym.imp.__cxa_finalize
0x55f7d18fd5f0    1 10           entry.init0
0x55f7d18fd6b0    1 2            sym.__libc_csu_fini
0x55f7d18fd6b4    1 9            sym._fini
0x55f7d18fd640    4 101          sym.__libc_csu_init
0x55f7d18fd5fa    4 66           main
0x55f7d18fd4b8    3 23           sym._init
[0x7f9f27960090]> pdf @main
/ (fcn) main 66
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_ch @ rbp-0xc
|           ; var int32_t var_8h @ rbp-0x8
|           ; var int32_t var_4h @ rbp-0x4
|           ; DATA XREF from entry0 (0x55f7d18fd50d)
|           0x55f7d18fd5fa      55             pushq %rbp
|           0x55f7d18fd5fb      4889e5         movq %rsp, %rbp
|           0x55f7d18fd5fe      c745f4140000.  movl $0x14, var_ch      ; 20
|           0x55f7d18fd605      c745f8160000.  movl $0x16, var_8h      ; 22
|           0x55f7d18fd60c      c745fc000000.  movl $0, var_4h
|           0x55f7d18fd613      c745fc040000.  movl $4, var_4h
|       ,=< 0x55f7d18fd61a      eb13           jmp 0x55f7d18fd62f
|      .--> 0x55f7d18fd61c      8365f402       andl $2, var_ch
|      :|   0x55f7d18fd620      d17df8         sarl $1, var_8h
|      :|   0x55f7d18fd623      8b55fc         movl var_4h, %edx
|      :|   0x55f7d18fd626      89d0           movl %edx, %eax
|      :|   0x55f7d18fd628      01c0           addl %eax, %eax
|      :|   0x55f7d18fd62a      01d0           addl %edx, %eax
|      :|   0x55f7d18fd62c      8945fc         movl %eax, var_4h
|      :|   ; CODE XREF from main (0x55f7d18fd61a)
|      :`-> 0x55f7d18fd62f      837dfc63       cmpl $0x63, var_4h      ; 'c'
|      `==< 0x55f7d18fd633      7ee7           jle 0x55f7d18fd61c
|           0x55f7d18fd635      b800000000     movl $0, %eax
|           0x55f7d18fd63a      5d             popq %rbp
\           0x55f7d18fd63b      c3             retq
[0x7f9f27960090]> 
```

On prépare le binaire et on regarde la fonction main.    

**What is the value of var_8h on the second iteration of the loop?**

```bash 
[0x7fd82b47c090]> db 0x561f8c00e62c

[0x7fd82b47c090]> dc
hit breakpoint at: 561f8c00e62c
[0x561f8c00e62c]> dc
hit breakpoint at: 561f8c00e62c

[0x561f8c00e62c]> pfi @rbp-0x8
0x7fff1cca03f8 = 5
```

On met un breakpoint à la fin de la boucle.  
On exécute  2 fois la boucle.   
Et on regarde la valeur.   
Réponse : 5. 

**What is the value of var_ch on the second iteration of the loop?**

```bash
[0x7fd82b47c090]> db 0x561f8c00e62c

[0x7fd82b47c090]> dc
hit breakpoint at: 561f8c00e62c
[0x561f8c00e62c]> dc
hit breakpoint at: 561f8c00e62c

[0x561f8c00e62c]> pfi @rbp-0xc
0x7fff1cca03f4 = 0
```

Même méthode que au dessus.   
La réponse est : 0  

** What is the value of var_8h at the end of the program? **

```bash
[0x7f46586f7090]> db 0x55a99a1aa63a 

0x7f46586f7090]> dc
hit breakpoint at: 55a99a1aa63a

[0x55a99a1aa63a]> pfi @rbp-0x8
0x7fff969fc7a8 = 2
```

On met un breakpoint à la fin de la fonction main.   
On regarde la valeur.   
Réponse : 2  

** What is the value of var_ch at the end of the program? **  

```bash
[0x7f46586f7090]> db 0x55a99a1aa63a 

0x7f46586f7090]> dc
hit breakpoint at: 55a99a1aa63a

[0x55a99a1aa63a]> pfi @rbp-0xc
0x7fff969fc7a4 = 0
```

Même chose que ci dessus.
Réponse : 0  

## Task 6 crackme1 ##

```bash
tryhackme@ip-10-10-191-174:~/crackme$ r2 -d crackme1 
Process with PID 16152 started...
= attach 16152 16152
bin.baddr 0x5607d83b5000
Using 0x5607d83b5000
asm.bits 64
 -- Can you stand on your head?
[0x7f7d39bad090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.tions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f7d39bad090]> afl
0x5607d83b56f0    1 42           entry0
0x5607d85b5fe0    1 4124         reloc.__libc_start_main
0x5607d83b5720    4 50   -> 40   sym.deregister_tm_clones
0x5607d83b5760    4 66   -> 57   sym.register_tm_clones
0x5607d83b57b0    5 58   -> 51   entry.fini0
0x5607d83b56e0    1 6            sym..plt.got
0x5607d83b57f0    1 10           entry.init0
0x5607d83b5990    1 2            sym.__libc_csu_fini
0x5607d83b5994    1 9            sym._fini
0x5607d83b5920    4 101          sym.__libc_csu_init
0x5607d83b57fa   10 280          main
0x5607d83b5650    3 23           sym._init
0x5607d83b5680    1 6            sym.imp.puts
0x5607d83b5690    1 6            sym.imp.strlen
0x5607d83b56a0    1 6            sym.imp.__stack_chk_fail
0x5607d83b5000    2 25           map.home_tryhackme_crackme_crackme1.r_x
0x5607d83b56b0    1 6            sym.imp.strcmp
0x5607d83b56c0    1 6            sym.imp.strtok
0x5607d83b56d0    1 6            sym.imp.__isoc99_scanf
[0x7f7d39bad090]> pdf @main
/ (fcn) main 280
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_54h @ rbp-0x54
|           ; var int32_t var_50h @ rbp-0x50
|           ; var int32_t var_4ch @ rbp-0x4c
|           ; var int32_t var_48h @ rbp-0x48
|           ; var int32_t var_40h @ rbp-0x40
|           ; var int32_t var_38h @ rbp-0x38
|           ; var int32_t var_30h @ rbp-0x30
|           ; var int32_t var_28h @ rbp-0x28
|           ; var int32_t var_12h @ rbp-0x12
|           ; var int32_t var_8h @ rbp-0x8
|           ; arg int32_t arg_40h @ rbp+0x40
|           ; DATA XREF from entry0 (0x5607d83b570d)
|           0x5607d83b57fa      55             pushq %rbp
|           0x5607d83b57fb      4889e5         movq %rsp, %rbp
|           0x5607d83b57fe      4883ec60       subq $0x60, %rsp        ; '`'
|           0x5607d83b5802      64488b042528.  movq %fs:0x28, %rax     ; [0x28:8]=-1 ; '(' ; 40
|           0x5607d83b580b      488945f8       movq %rax, var_8h
|           0x5607d83b580f      31c0           xorl %eax, %eax
|           0x5607d83b5811      488d3d900100.  leaq str.enter_your_password, %rdi ; 0x5607d83b59a8 ; "enter your password"
|           0x5607d83b5818      e863feffff     callq sym.imp.puts      ; int puts(const char *s)
|           0x5607d83b581d      488d45ee       leaq var_12h, %rax
|           0x5607d83b5821      4889c6         movq %rax, %rsi
|           0x5607d83b5824      488d3d910100.  leaq 0x5607d83b59bc, %rdi ; "%s"
|           0x5607d83b582b      b800000000     movl $0, %eax
|           0x5607d83b5830      e89bfeffff     callq sym.imp.__isoc99_scanf ; int scanf(const char *format)
|           0x5607d83b5835      c745ac000000.  movl $0, var_54h
|           0x5607d83b583c      488d057c0100.  leaq 0x5607d83b59bf, %rax ; "127"
|           0x5607d83b5843      488945c0       movq %rax, var_40h
|           0x5607d83b5847      488d05750100.  leaq str.01., %rax      ; 0x5607d83b59c3 ; u"01.\u7257\u6e6f\u2067\u6150\u7373\u6f77\u6472\u5900\u756f\u7627\u2065\u6f67\u2074\u6874\u2065\u6f63\u7272\u6365\u2074\u6170\u7373\u6f77\u6472\u0100\u031b\u3c3b"
|           0x5607d83b584e      488945c8       movq %rax, var_38h
|           0x5607d83b5852      488d056a0100.  leaq str.01., %rax      ; 0x5607d83b59c3 ; u"01.\u7257\u6e6f\u2067\u6150\u7373\u6f77\u6472\u5900\u756f\u7627\u2065\u6f67\u2074\u6874\u2065\u6f63\u7272\u6365\u2074\u6170\u7373\u6f77\u6472\u0100\u031b\u3c3b"
|           0x5607d83b5859      488945d0       movq %rax, var_30h
|           0x5607d83b585d      488d05610100.  leaq 0x5607d83b59c5, %rax ; u"1.\u7257\u6e6f\u2067\u6150\u7373\u6f77\u6472\u5900\u756f\u7627\u2065\u6f67\u2074\u6874\u2065\u6f63\u7272\u6365\u2074\u6170\u7373\u6f77\u6472\u0100\u031b\u3c3b"
|           0x5607d83b5864      488945d8       movq %rax, var_28h
|           0x5607d83b5868      488d45ee       leaq var_12h, %rax
|           0x5607d83b586c      4889c7         movq %rax, %rdi
|           0x5607d83b586f      e81cfeffff     callq sym.imp.strlen    ; size_t strlen(const char *s)
|           0x5607d83b5874      8945b0         movl %eax, var_50h
|           0x5607d83b5877      488d45ee       leaq var_12h, %rax
|           0x5607d83b587b      488d35450100.  leaq 0x5607d83b59c7, %rsi ; "."
|           0x5607d83b5882      4889c7         movq %rax, %rdi
|           0x5607d83b5885      e836feffff     callq sym.imp.strtok    ; char *strtok(char *s1, const char *s2)
|           0x5607d83b588a      488945b8       movq %rax, var_48h
|       ,=< 0x5607d83b588e      eb4e           jmp 0x5607d83b58de
|      .--> 0x5607d83b5890      8b45ac         movl var_54h, %eax
|      :|   0x5607d83b5893      4898           cltq
|      :|   0x5607d83b5895      488b54c5c0     movq -0x40(%rbp, %rax, 8), %rdx
|      :|   0x5607d83b589a      488b45b8       movq var_48h, %rax
|      :|   0x5607d83b589e      4889d6         movq %rdx, %rsi
|      :|   0x5607d83b58a1      4889c7         movq %rax, %rdi
|      :|   0x5607d83b58a4      e807feffff     callq sym.imp.strcmp    ; int strcmp(const char *s1, const char *s2)
|      :|   0x5607d83b58a9      8945b4         movl %eax, var_4ch
|      :|   0x5607d83b58ac      8345ac01       addl $1, var_54h
|      :|   0x5607d83b58b0      837db400       cmpl $0, var_4ch
|     ,===< 0x5607d83b58b4      7413           je 0x5607d83b58c9
|     |:|   0x5607d83b58b6      488d3d0c0100.  leaq 0x5607d83b59c9, %rdi ; "Wrong Password"
|     |:|   0x5607d83b58bd      e8befdffff     callq sym.imp.puts      ; int puts(const char *s)
|     |:|   0x5607d83b58c2      b8ffffffff     movl $0xffffffff, %eax  ; -1
|    ,====< 0x5607d83b58c7      eb33           jmp 0x5607d83b58fc
|    |`---> 0x5607d83b58c9      488d35f70000.  leaq 0x5607d83b59c7, %rsi ; "."
|    | :|   0x5607d83b58d0      bf00000000     movl $0, %edi
|    | :|   0x5607d83b58d5      e8e6fdffff     callq sym.imp.strtok    ; char *strtok(char *s1, const char *s2)
|    | :|   0x5607d83b58da      488945b8       movq %rax, var_48h
|    | :|   ; CODE XREF from main (0x5607d83b588e)
|    | :`-> 0x5607d83b58de      48837db800     cmpq $0, var_48h
|    | :,=< 0x5607d83b58e3      7406           je 0x5607d83b58eb
|    | :|   0x5607d83b58e5      837dac03       cmpl $3, var_54h
|    | `==< 0x5607d83b58e9      7ea5           jle 0x5607d83b5890
|    |  `-> 0x5607d83b58eb      488d3de60000.  leaq str.You_ve_got_the_correct_password, %rdi ; 0x5607d83b59d8 ; "You've got the correct password"
|    |      0x5607d83b58f2      e889fdffff     callq sym.imp.puts      ; int puts(const char *s)
|    |      0x5607d83b58f7      b800000000     movl $0, %eax
|    |      ; CODE XREF from main (0x5607d83b58c7)
|    `----> 0x5607d83b58fc      488b4df8       movq var_8h, %rcx
|           0x5607d83b5900      6448330c2528.  xorq %fs:0x28, %rcx
|       ,=< 0x5607d83b5909      7405           je 0x5607d83b5910
|       |   0x5607d83b590b      e890fdffff     callq sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x5607d83b5910      c9             leave
\           0x5607d83b5911      c3             retq
``` 

On prépare la programme, on regarde la fonction main.   

A l'adresse  0x5607d83b5885 on remarque qu'il y a une comparaison entre de chaînes.   

```bash
[0x7f7d39bad090]> db 0x5607d83b58a4
[0x7f7d39bad090]> dc
enter your password
1234
hit breakpoint at: 0x5607d83b58a4

[0x558f741cc8a4]> dr
rax = 0x7fff3b42a6de
rbx = 0x00000000
rcx = 0x00000002
rdx = 0x558f741cc9bf
r8 = 0x0000000e
r9 = 0x00000000
r10 = 0x00000000
r11 = 0x558f741cc9be
r12 = 0x558f741cc6f0
r13 = 0x7fff3b42a7d0
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x558f741cc9bf
rdi = 0x7fff3b42a6de
rsp = 0x7fff3b42a690
rbp = 0x7fff3b42a6f0
rip = 0x558f741cc8a4
rflags = 0x00000293
orax = 0xffffffffffffffff

[0x558f741cc8a4]> px @0x0x558f741cc9bf
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x558f741cc9bf  3132 3700 3000 3100 2e00 5772 6f6e 6720  127.0.1...Wrong 
0x558f741cc9cf  5061 7373 776f 7264 0059 6f75 2776 6520  Password.You've 
0x558f741cc9df  676f 7420 7468 6520 636f 7272 6563 7420  got the correct 
0x558f741cc9ef  7061 7373 776f 7264 0001 1b03 3b3c 0000  password....;<..
0x558f741cc9ff  0006 0000 0078 fcff ff88 0000 00e8 fcff  .....x..........
0x558f741cca0f  ffb0 0000 00f8 fcff ff58 0000 0002 feff radar2 show $0 ;*3$"........D..
0x558f741ccaaf  0030 fcff ff08 0000 0000 0000 0000 0000  .0..............

```

On met un breakpoint sur la fonction sur l'appel du la fonction strcmp.  
La fonction strcmp prend deux argument notre chaîne dans le registre rdi et l'autre chaîne a comparer dans le registre rsi.  
Regardons sur quoi pointe rdi, quand on regarde à l'adresse rdi on remarque la chaîne 127 0 1.  

```bash
[0x7fdfda122090]> db @0x55d1a72d68d5
[0x7f4eca3b6090]> dc
enter your password
127.
You've got the correct password
```

On a une fonction strstok qui sert sépare les valeurs, le séparateur ici est le . on le voit à l'adresse 0x5607d83b58c9.  
Ici j'ai un bon mot de passe car le programme à été mal codé, il vérifie pas correctement les variables séparés.  

D'après la valeur 127.0.1 on peut suppose le que bon mot de passe est 127.0.0.1
Réponse : 127.0.0.1   

## Task 7 crackme2 ##

```bash
tryhackme@ip-10-10-191-174:~/crackme$ r2 -d crackme2
Process with PID 16188 started...
= attach 16188 16188
bin.baddr 0x560d1307c000
Using 0x560d1307c000
asm.bits 64
 -- There's more than one way to skin a cat
[0x7f88da355090]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
Warning: Invalid range. Use different search.in=? or anal.in=dbg.maps.x
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[TOFIX: aaft can't run in debugger mode.ions (aaft)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f88da355090]> afl
0x560d1307c6f0    1 42           entry0
0x560d1327cfe0    1 4124         reloc.__libc_start_main
0x560d1307c720    4 50   -> 40   sym.deregister_tm_clones
0x560d1307c760    4 66   -> 57   sym.register_tm_clones
0x560d1307c7b0    5 58   -> 51   entry.fini0
0x560d1307c6e0    1 6            sym..plt.got
0x560d1307c7f0    1 10           entry.init0
0x560d1307c990    1 2            sym.__libc_csu_fini
0x560d1307c994    1 9            sym._fini
0x560d1307c920    4 101          sym.__libc_csu_init
0x560d1307c7fa   12 283          main
0x560d1307c650    3 23           sym._init
0x560d1307c680    1 6            sym.imp.puts
0x560d1307c690    1 6            sym.imp.fread
0x560d1307c6a0    1 6            sym.imp.strlen
0x560d1307c6b0    1 6            sym.imp.__stack_chk_fail
0x560d1307c000    2 25           map.home_tryhackme_crackme_crackme2.r_x
0x560d1307c6c0    1 6            sym.imp.fopen
0x560d1307c6d0    1 6            sym.imp.__isoc99_scanf
[0x7f88da355090]> pdf @main
/ (fcn) main 283
|   int main (int argc, char **argv, char **envp);
|           ; var int32_t var_44h @ rbp-0x44
|           ; var int32_t var_40h @ rbp-0x40
|           ; var int32_t var_3ch @ rbp-0x3c
|           ; var int32_t var_38h @ rbp-0x38
|           ; var int32_t var_2eh @ rbp-0x2e
|           ; var int32_t var_23h @ rbp-0x23
|           ; var int32_t var_18h @ rbp-0x18
|           ; DATA XREF from entry0 (0x560d1307c70d)
|           0x560d1307c7fa      55             pushq %rbp
|           0x560d1307c7fb      4889e5         movq %rsp, %rbp
|           0x560d1307c7fe      53             pushq %rbx
|           0x560d1307c7ff      4883ec48       subq $0x48, %rsp        ; 'H'
|           0x560d1307c803      64488b042528.  movq %fs:0x28, %rax     ; [0x28:8]=-1 ; '(' ; 40
|           0x560d1307c80c      488945e8       movq %rax, var_18h
|           0x560d1307c810      31c0           xorl %eax, %eax
|           0x560d1307c812      488d358f0100.  leaq 0x560d1307c9a8, %rsi ; "r"
|           0x560d1307c819      488d3d900100.  leaq str.home_tryhackme_install_files_secret.txt, %rdi ; 0x560d1307c9b0 ; "/home/tryhackme/install-files/secret.txt"
|           0x560d1307c820      e89bfeffff     callq sym.imp.fopen     ; file*fopen(const char *filename, const char *mode)
|           0x560d1307c825      488945c8       movq %rax, var_38h
|           0x560d1307c829      488b55c8       movq var_38h, %rdx
|           0x560d1307c82d      488d45d2       leaq var_2eh, %rax
|           0x560d1307c831      4889d1         movq %rdx, %rcx
|           0x560d1307c834      ba0b000000     movl $0xb, %edx         ; 11
|           0x560d1307c839      be01000000     movl $1, %esi
|           0x560d1307c83e      4889c7         movq %rax, %rdi
|           0x560d1307c841      e84afeffff     callq sym.imp.fread     ; size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
|           0x560d1307c846      8945c4         movl %eax, var_3ch
|           0x560d1307c849      837dc400       cmpl $0, var_3ch
|       ,=< 0x560d1307c84d      7916           jns 0x560d1307c865
|       |   0x560d1307c84f      488d3d830100.  leaq str.Error_Reading_File, %rdi ; 0x560d1307c9d9 ; "Error Reading File"
|       |   0x560d1307c856      e825feffff     callq sym.imp.puts      ; int puts(const char *s)
|       |   0x560d1307c85b      b8ffffffff     movl $0xffffffff, %eax  ; -1
|      ,==< 0x560d1307c860      e995000000     jmp 0x560d1307c8fa
|      |`-> 0x560d1307c865      488d3d800100.  leaq str.Please_enter_password, %rdi ; 0x560d1307c9ec ; "Please enter password"
|      |    0x560d1307c86c      e80ffeffff     callq sym.imp.puts      ; int puts(const char *s)
|      |    0x560d1307c871      488d45dd       leaq var_23h, %rax
|      |    0x560d1307c875      4889c6         movq %rax, %rsi
|      |    0x560d1307c878      488d3d830100.  leaq str.11s, %rdi      ; 0x560d1307ca02 ; "%11s"
|      |    0x560d1307c87f      b800000000     movl $0, %eax
|      |    0x560d1307c884      e847feffff     callq sym.imp.__isoc99_scanf ; int scanf(const char *format)
|      |    0x560d1307c889      c745bc090000.  movl $9, var_44h
|      |    0x560d1307c890      c745c0000000.  movl $0, var_40h
|      |,=< 0x560d1307c897      eb33           jmp 0x560d1307c8cc
|     .---> 0x560d1307c899      8b45bc         movl var_44h, %eax
|     :||   0x560d1307c89c      4898           cltq
|     :||   0x560d1307c89e      0fb65405d2     movzbl -0x2e(%rbp, %rax), %edx
|     :||   0x560d1307c8a3      8b45c0         movl var_40h, %eax
|     :||   0x560d1307c8a6      4898           cltq
|     :||   0x560d1307c8a8      0fb64405dd     movzbl -0x23(%rbp, %rax), %eax
|     :||   0x560d1307c8ad      38c2           cmpb %al, %dl
|    ,====< 0x560d1307c8af      7413           je 0x560d1307c8c4
|    |:||   0x560d1307c8b1      488d3d4f0100.  leaq str.Wrong_Password, %rdi ; 0x560d1307ca07 ; "Wrong Password"
|    |:||   0x560d1307c8b8      e8c3fdffff     callq sym.imp.puts      ; int puts(const char *s)
|    |:||   0x560d1307c8bd      b8ffffffff     movl $0xffffffff, %eax  ; -1
|   ,=====< 0x560d1307c8c2      eb36           jmp 0x560d1307c8fa
|   |`----> 0x560d1307c8c4      836dbc01       subl $1, var_44h
|   | :||   0x560d1307c8c8      8345c001       addl $1, var_40h
|   | :||   ; CODE XREF from main (0x560d1307c897)
|   | :|`-> 0x560d1307c8cc      837dbc00       cmpl $0, var_44h
|   | :|,=< 0x560d1307c8d0      7e17           jle 0x560d1307c8e9
|   | :||   0x560d1307c8d2      8b45c0         movl var_40h, %eax
|   | :||   0x560d1307c8d5      4863d8         movslq %eax, %rbx
|   | :||   0x560d1307c8d8      488d45dd       leaq var_23h, %rax
|   | :||   0x560d1307c8dc      4889c7         movq %rax, %rdi
|   | :||   0x560d1307c8df      e8bcfdffff     callq sym.imp.strlen    ; size_t strlen(const char *s)
|   | :||   0x560d1307c8e4      4839c3         cmpq %rax, %rbx
|   | `===< 0x560d1307c8e7      72b0           jb 0x560d1307c899
|   |  |`-> 0x560d1307c8e9      488d3d260100.  leaq str.Correct_Password, %rdi ; 0x560d1307ca16 ; "Correct Password"
|   |  |    0x560d1307c8f0      e88bfdffff     callq sym.imp.puts      ; int puts(const char *s)
|   |  |    0x560d1307c8f5      b800000000     movl $0, %eax
|   |  |    ; CODE XREFS from main (0x560d1307c860, 0x560d1307c8c2)
|   `--`--> 0x560d1307c8fa      488b4de8       movq var_18h, %rcx
|           0x560d1307c8fe      6448330c2528.  xorq %fs:0x28, %rcx
|       ,=< 0x560d1307c907      7405           je 0x560d1307c90e
|       |   0x560d1307c909      e8a2fdffff     callq sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
|       `-> 0x560d1307c90e      4883c448       addq $0x48, %rsp        ; 'H'
|           0x560d1307c912      5b             popq %rbx
|           0x560d1307c913      5d             popq %rbp
\           0x560d1307c914      c3             retq
```

On prépare le fichier.  
L'adresse 0x560d1307c819 on remarque le programme ouvre un fichier a l'endroit \/home\/tryhackme\/install-files\/secret.txt.   

```bash
tryhackme@ip-10-10-191-174:~/crackme$ cat /home/tryhackme/install-files/secret.txt 
vs3curepwd
```

Il y a un mot de passe dedans essayons le.  

```bash
tryhackme@ip-10-10-191-174:~/crackme$ ./crackme2
Please enter password
vs3curepwd
Wrong Password
```

zut ça ne fonctionne pas.

```bash
[0x7f2d502ef090]> db 0x560d1307c8ad
[0x7f2d502ef090]> dc
Please enter password
vs3curepwd
hit breakpoint at: 0x560d1307c8ad
[0x55f28e9e98ad]> dr al
0x00000076
[0x55f28e9e98ad]> dr dl
0x00000064
```

A l'adresse 0x55f28e9e98ad on met un break point il y une comparaison entre deux valeurs.  
Les valeurs sont en hexadécimal , mais on reconnait que c'est l'ASCII.  
76 vaut v en ASCII.  
64 vaut d en ASCII.

Donc on c'est que v est la premiere lettre donc notre mot de passe.  
La bonne valeur attendu est d.  
Ca ressemble la fin de notre motre de passe. 

```bash
[0x7f2d502ef090]> db 0x560d1307c8ad
[0x7f2d502ef090]> dc
Please enter password
dwperuc3sv
hit breakpoint at: 0x560d1307c8ad

[0x56249975b8ad]> dr al
0x00000064
[0x56249975b8ad]> dr dl
0x00000064

[0x56249975b8ad]> dc 
hit breakpoint at: 0x560d1307c8ad

[0x56249975b8ad]> dr al
0x00000077
[0x56249975b8ad]> dr dl
0x00000077
```

On inversant le mot de passe les deux premiers caractères sont bon.    

```bash
[0x56249975b8ad]> db -560d1307c8ad
[0x56249975b8ad]> dc
Correct Password
```

On enlève le breakpoint et on voit que c'est le bon mot de passe.   

```bash
tryhackme@ip-10-10-191-174:~/crackme$ ./crackme2 
Please enter password
dwperuc3sv
Correct Password
```

La réponse est : dwperuc3sv   


