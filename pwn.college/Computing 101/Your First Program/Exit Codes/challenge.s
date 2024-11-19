mov rax, 60     # number syscall exit()
mov rdi,42      # exit code number
syscall         # call syscall
