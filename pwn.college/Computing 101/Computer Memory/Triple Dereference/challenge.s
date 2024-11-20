mov rdi,[rdi]       # 1 deference
mov rdi,[rdi]       # 2 deference
mov rdi,[rdi]       # 3 deference
mov rax,60          # syscall exit()
syscall             # call syscall
