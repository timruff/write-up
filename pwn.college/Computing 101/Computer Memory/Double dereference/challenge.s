mov rax,[rax]       # one dereference
mov rdi,[rax]       # two dereference
mov rax,60          # syscall exit()
syscall             # call syscall
