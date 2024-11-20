.intel_syntax noprefix
# version longue
# and rax,0x000000000000000F # masque on garde que al
# and dil,0b00000001 # on garde que le dernier bit
# and al, 0b00000001 # on met que 1 al pour le xor voir table
# xor al,dil

# version courte
and rdi,1 
and rax,1
xor rax,rdi
