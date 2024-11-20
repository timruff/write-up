mov rdi,[rdi]       # dereferencing youself
mov rax,60          # syscall exit()
syscall             # call syscall
