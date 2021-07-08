# CC: Radare2 #

***

## Task 1 Intro ##

Avant de commencer cette épreuve il est fortement recommender de faire le cour Intro to x86-64 de tryhackme.

***

## Task 2 Command Line Options ##

Toutes les réponses sont dans l'aide de radare2 faite : **radare2 -h** 

***

## Task 3 Analyzation ##

Pour les trois première question la commande **aa? a?** et **af?** vous donne les réponses.

** How many functions are in the example1 binary?**

Pour cette question il faut utiliser afl voici la procédure ci dessous.

```bash
tim@kali:~/Bureau/tryhackme/cc/z$ radare2 example1 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00000530]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000530]> afl
0x00000530    1 42           entry0
0x00000560    4 50   -> 44   sym.deregister_tm_clones
0x000005a0    4 66   -> 57   sym.register_tm_clones
0x000005f0    5 50           sym.__do_global_dtors_aux
0x00000520    1 6            sym.imp.__cxa_finalize
0x00000630    4 48   -> 42   entry.init0
0x000004f8    3 23           sym._init
0x000006e0    1 1            sym.__libc_csu_fini
0x000006e4    1 9            sym._fini
0x0000066b    1 7            sym.*************
0x00000680    4 93           sym.__libc_csu_init
0x00000660    1 11           main
0x00000000    3 97   -> 123  loc.imp._ITM_deregisterTMCloneTable
[0x00000530]> 
```

Il suffit de compter toutes les lignes sauf main qui est pas une fonction, si vous avez du mal compter les lignes wc peut le faire à votre place.

**What is the name of the secret function in the example1 binary?**

Il suffit filtrer le motif secret par example avec grep : **afl | grep secret**.

***

## Task 4 Information ##

Pour les 5 premières questions les réponses se trouvent dans l'aide avec la commande **i?**.

**What is the secret string hidden in the example2 binary?**

Pour répondre à la question ci dessous faire **izz** regardez la chaîne qui indique une phrase, example ci-dessous.

```bash
tim@kali:~/Bureau/tryhackme/cc/z$ radare2 example2
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00000530]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000530]> izz | grep -v -F '.'
[Strings]
nth paddr      vaddr      len size section            type    string
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000034 0x00000034 4   10                      utf16le @8\t@
80  0x00002148 0x00000882 8   8                       ascii   *******\n
[0x00000530]> 
```

***

## Task 5 Navigating Through Memory ##

Toutes réponses sont disponibles avec la commande **s?**.

***

## Task 6 Printing ##

Pour les 5 premières question les réponses sont disponible avec la commande **p?** **px** et **@?**.

Pour les deux dernière question il suffit de désassembler la fonction main avec la commande **pd @ main**
Voir example ci-dessous.

```bash
tim@kali:~/Bureau/tryhackme/cc/z$ radare2 example3 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00000530]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000530]> pd @ main
            ; DATA XREF from entry0 @ 0x54d
┌ 25: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8                        # nom variable 1
│           ; var int64_t var_4h @ rbp-0x4                        # nom variable 2
│           0x00000660      55             push rbp
│           0x00000661      4889e5         mov rbp, rsp
│           0x00000664      c745fc010000.  mov dword [var_4h], *  # valeur variable 1
│           0x0000066b      c745f8050000.  mov dword [var_8h], *  # valeur variable 2
│           0x00000672      b800000000     mov eax, 0
│           0x00000677      5d             pop rbp
└           0x00000678      c3             ret
```

***

# Task 7  The Mid-term #

Ici on test tout ce que l'on a apprit dans les sections précédentes.

**How many functions are in the binary?**

```bash
tim@kali:~/Bureau/tryhackme/cc/z$ radare2 midterm 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x00000530]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x00000530]> afl | wc -l
** # solution - 1
```

**What is the value of the hidden string?**

```bash
[0x00000530]> izz | grep -v -F '.'
[Strings]
nth paddr      vaddr      len size section   type    string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000034 0x00000034 4   10             utf16le @8\t@
82  0x00002178 0x00000887 14  14             ascii   solution
```

**What is the return value of secret_func()?**

```bash
[0x00000530]> pd @ sym.secret_func
┌ 11: sym.secret_func ();
│           0x00000680      55             push rbp
│           0x00000681      4889e5         mov rbp, rsp
│           0x00000684      b804000000     mov eax, * # solution
│           0x00000689      5d             pop rbp
└           0x0000068a      c3             ret
            0x0000068b      0f1f440000     nop dword [rax + rax]
            ; DATA XREF from entry0 @ 0x546
```

**What is the value of the first variable set in the main function(in decimal format)?**
**What about the second one(also in decimal format)?**

``` bash
[0x00000530]> pd @ main
            ; DATA XREF from entry0 @ 0x54d
┌ 25: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_4h @ rbp-0x4
│           0x00000660      55             push rbp
│           0x00000661      4889e5         mov rbp, rsp
│           0x00000664      c745fc0c0000.  mov dword [var_4h], 0x*      # solution 1 er question ci-dessus
│           0x0000066b      c745f8c00000.  mov dword [var_8h], 0x**     # solution 2 eme question ci-dessus
│           0x00000672      b800000000     mov eax, 0
│           0x00000677      5d             pop rbp
└           0x00000678      c3             ret
```

**What is the next function in memory after the main function?**

```bash
[0x00000530]> afl | sort | grep main -A 1
0x00000660    1 25           main
0x00000679    1 7            ********  # solution
```

La commande sort permet de trier les adresse de plus petit au plus grand.

**How do you get a hexdump of four bytes of the memory address your currently at?**
voir commentaire p? 

***

## Task 8 Debugging ##

On peut répondre à toutes les questions avec d? et db?.

***

## Task 9 Visual Mode ##

On répond avec v? et v, faite des tests et c'est bon.

***

## Task 10 Write Mode ##

On peut répondre aux questions avec w?.

***

## Task 11 Final Exam ##

``` bash 
[0x000006a0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000006a0]> 
0x000006a0]> afl
0x000006a0    1 42           entry0
0x000006d0    4 50   -> 44   sym.deregister_tm_clones
0x00000710    4 66   -> 57   sym.register_tm_clones
0x00000760    5 50           sym.__do_global_dtors_aux
0x00000690    1 6            sym.imp.__cxa_finalize
0x000007a0    4 48   -> 42   entry.init0
0x00000620    3 23           sym._init
0x00000900    1 1            sym.__libc_csu_fini
0x00000904    1 9            sym._fini
0x000008a0    4 93           sym.__libc_csu_init
0x00000835    3 102          main
0x00000660    1 6            sym.imp.fgets
0x000007d0    4 101          sym.get_password
0x00000670    1 6            sym.imp.strcmp
0x00000650    1 6            sym.imp.printf
0x00000000    6 292  -> 318  loc.imp._ITM_deregisterTMCloneTable
0x00000680    1 6            sym.imp.malloc
[0x000006a0]> 
```

On listes les fonctions.
Regardons la fonctions main

```bash
tim@kali:~/Bureau/tryhackme/cc/z$ radare2 the_final_exam 
Warning: run r2 with -e io.cache=true to fix relocations in disassembly
[0x000006a0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000006a0]> ood
Process with PID 2467 started...
= attach 2467 2467
File dbg:///home/tim/Bureau/tryhackme/cc/z/the_final_exam  reopened in read-write mode
2467
[0x7fe759247090]> pdf @ main
            ; DATA XREF from entry0 @ 0x55a0b9e006bd
┌ 102: int main (int argc, char **argv, char **envp);
│           ; var char *s @ rbp-0x11
│           ; var char *s1 @ rbp-0x8
│           0x55a0b9e00835      55             push rbp
│           0x55a0b9e00836      4889e5         mov rbp, rsp
│           0x55a0b9e00839      4883ec20       sub rsp, 0x20
│           0x55a0b9e0083d      488b150c0820.  mov rdx, qword [obj.stdin] ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x55a0ba001050:8]=0 ; FILE *stream
│           0x55a0b9e00844      488d45ef       lea rax, [rbp - 0x11]
│           0x55a0b9e00848      be09000000     mov esi, 9              ; int size
│           0x55a0b9e0084d      4889c7         mov rdi, rax            ; char *s
│           0x55a0b9e00850      e80bfeffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
│           0x55a0b9e00855      488d45ef       lea rax, [rbp - 0x11]
│           0x55a0b9e00859      4889c7         mov rdi, rax            ; int64_t arg1
│           0x55a0b9e0085c      e86fffffff     call sym.get_password
│           0x55a0b9e00861      488945f8       mov qword [rbp - 8], rax
│           0x55a0b9e00865      488b45f8       mov rax, qword [rbp - 8]
│           0x55a0b9e00869      488d35a40000.  lea rsi, str.youdidit   ; 0x55a0b9e00914 ; "youdidit" ; const char *s2
│           0x55a0b9e00870      4889c7         mov rdi, rax            ; const char *s1
│           0x55a0b9e00873      e8f8fdffff     call sym.imp.strcmp     ; int strcmp(const char *s1, const char *s2)
│           0x55a0b9e00878      85c0           test eax, eax
│       ┌─< 0x55a0b9e0087a      7518           jne 0x55a0b9e00894
│       │   0x55a0b9e0087c      488d359a0000.  lea rsi, str.You_win_   ; 0x55a0b9e0091d ; "You win!"
│       │   0x55a0b9e00883      488d3d9c0000.  lea rdi, [0x55a0b9e00926] ; "%s" ; const char *format
│       │   0x55a0b9e0088a      b800000000     mov eax, 0
│       │   0x55a0b9e0088f      e8bcfdffff     call sym.imp.printf     ; int printf(const char *format)
│       │   ; CODE XREF from main @ 0x55a0b9e0087a
│       └─> 0x55a0b9e00894      b800000000     mov eax, 0
│           0x55a0b9e00899      c9             leave
└           0x55a0b9e0089a      c3             ret
```

Ici on remarque une chose intéressante la chaîne "youdidit" et le faite quelle est comparée par une autre chaîne par la fonction sym.imp.strcmp

On voit que notre saisie est chiffrée pas la fonction sym.get_password.
Le résultat est mis dans le registre rax.
Mettons un break point et regardons eax.

 ``` bash
[0x7f688105a090]> db 0x556472200861 
[0x7f688105a090]> dc
12345678
hit breakpoint at: 0x556472200861
[0x556472200861]> dr
rax = 0x5564738736b0
rbx = 0x00000000
rcx = 0x5564738736c0
rdx = 0x5564738736b7
r8 = 0x5564738736b0
r9 = 0x7f688102dbe0
r10 = 0xfffffffffffff28d
r11 = 0x00000020
r12 = 0x5564722006a0
r13 = 0x00000000
r14 = 0x00000000
r15 = 0x00000000
rsi = 0x00000009
rdi = 0x5564738736b0
rsp = 0x7fff7b52bfe0
rbp = 0x7fff7b52c000
rip = 0x556472200861
rflags = 0x00000202
orax = 0xffffffffffffffff
[0x556472200861]> px @ 0x5564738736b0
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x5564738736b0  3b3c 3d3e 3f40 4142 0000 0000 0000 0000  ;<=>?@AB........
0x5564738736c0  0000 0000 0000 0000 4109 0200 0000 0000  ........A.......
0x5564738736d0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x5564738736e0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x5564738736f0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873700  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873710  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873720  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873730  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873740  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873750  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873760  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873770  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873780  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x556473873790  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x5564738737a0  0000 0000 0000 0000 0000 0000 0000 0000  ................

```

Ici on met un break point et on regarde sur quoi pointe l'adresse rax.  
On voit ici on à une chaîne ;<=>?@AB pour une saisie 12345678.  

Regardons ceci en code ascii 3b 3c 3d 3e 3f 40 41 42 ;<=>?@AB  
                             31 32 33 34 35 36 37 38 12345678  

Regardons la différence  
3b-31 = A ceci ce répète sur toute le chaîne essayons de refaire la chaîne youdidit  

youdidit 79 6F 75 64 69 64 69 74  
        - A  A  A  A  A  A  A  A  
        ------------------------
         6F 65 6B 5A 5F 5A 5F 6A  

Il y a plus que à convertir et on trouve la réponse.          