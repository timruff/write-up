mov rdi,[rdi+8]     # deferencing rdi of offset 8
mov rax,60          # syscall exit()
syscall             # call syscall
