mov rax, 60     # syscal number exit()
mov rdi,rsi     # store secret value rsi in rdi exit code
syscall         # call syscall exit
