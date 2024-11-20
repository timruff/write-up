mov rax,60          # number of syscall exit()
mov rdi,[123400]    # mov value at adress at 123400 in rdi
syscall             # call syscall
