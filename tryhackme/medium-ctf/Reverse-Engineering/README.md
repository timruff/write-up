# Reverse Engineering #

## Task 1 Debugging and File Permission ##

**Set up debugger(if you haven't already)**

On install ghidra et radar2.     

## Task 2 crackme1 ##

**what is the correct password**

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined4 local_1c;
  undefined2 local_18;
  char local_16 [6];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("enter password");
  local_1c = 0x30786168;
  local_18 = 0x72;
  __isoc99_scanf(&DAT_001008a3,local_16);
  iVar1 = strcmp(local_16,(char *)&local_1c);
  if (iVar1 == 0) {
    puts("password is correct");
  }
  else {
    puts("password is incorrect");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

On décompile de programme avec ghidra.   
On voit que le programme compare deux chaîne entre eux.   
La chaîne dans Local_16 est notre saisie pas __isoc99_scanf.  
La chaîne dans Local_1c = 0x30786468 et Local_18 qui est héxadécimal.   

Convertissons c'est chaîne en caractère ASCII.
78 30 78 61 68
r  0  x  a  h

Comme on est sur architecture little endianess on lit à l'envers la chaîne.   
qui donne hax0r.    

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ./crackme1.bin hax0r
enter password
hax0r
password is correct

```
La réponse est : hax0r    

## Task 3 crackme2 ##

**What is the correct password?**

On décompile avec ghidra

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("enter your password");
  __isoc99_scanf(&DAT_00100838,&local_14);
  if (local_14 == 0x137c) {
    puts("password is valid");
  }
  else {
    puts("password is incorrect");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

On voit que notre saisie est comparée avec la valeur 0x137c.    
La variable de notre saisie local_14 est un entier donc la valeur 0x137c est entière.    
On convertie 0x137c en héxadécimal en décimal.    
0x137c = 4988   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ./crackme2.bin 
enter your password
4988
password is valid
```

La réponse est : 4988     

## Task 4 crackme3 ##

**What are the first 3 letters of the correct password?**

On décompile le code avec ghidra.   

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  int local_30;
  undefined2 local_2b;
  undefined local_29;
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_2b = 0x7a61;
  local_29 = 0x74;
  puts("enter your password");
  __isoc99_scanf(&DAT_00100868,local_28);
  local_30 = 0;
  do {
    if (2 < local_30) {
      puts("password is correct");
LAB_001007ae:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    if (local_28[local_30] != *(char *)((long)&local_2b + (long)local_30)) {
      puts("password is incorrect");
      goto LAB_001007ae;
    }
    local_30 = local_30 + 1;
  } while( true );
}
```

On remarque la variable local_2b et local_29 avec des valeurs héxadécimal.
Considérons la variable local_29 fait partie intégrante de local_2b.
La valeur est 0x747a61.   
La variable de la saisie est Local28.  

On rentre dans une boucle do while.  

Elle se termine qui la variable Local 30 est supérieur 2 donc le password est bon.
C'est le nombre de caractères bon. 

La condition qui vérifie que la saisie est bonne, elle fait ceci :   
Elle test caractère par caractère la chaîne saisie avec la variable local_2b.   

Décomposons la chaîne 747a61.   
Comme c'est une architecture little endian on inverse.   
Qui done 617a74    

On simule la boucle.
0 
61 = a
1
7a = z
2
74 = t

Le mot passe est azt.   

```bash
tim@kali:~/Bureau/tryhackme/write-up$ ./crackme3.bin 
enter your password
azt
password is correct
```

La réponse est : azt     