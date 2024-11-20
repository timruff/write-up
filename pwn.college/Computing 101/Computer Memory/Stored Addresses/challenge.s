mov rax,[567800]        # get value at address 567800 and store to rax
mov rdi,[rax]           # get value pointed by rax to rdi
mov rax,60              # syscall exit()
syscall                 # call syscall
