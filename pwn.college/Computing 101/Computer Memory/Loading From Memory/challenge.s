mov rax, 60           # number syscall exit()
mov rdi,[133700]      # mov value at adress 31337 to rdi
syscall               # call syscall with value return get to rdi
