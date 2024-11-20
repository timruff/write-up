.intel_syntax noprefix 
xor rax,rax # initialise rax à 0 (si rax avec valeur inconnu)
or rax,rdi  # rax prend la valeur rdi
and rax,rsi # and rdi rsi

# and rax,rdi # première méthode si rax est au maximum
# and rax,rsi 
