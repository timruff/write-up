mov rax,1           # number syscall write()
mov rdi, 1          # fd 1 standard output
mov rsi, 1337000    # first adresse of string
mov rdx, 14         # one letter
syscall             # call syscall
mov rax,60          # number syscall exit()
mov rdi,42          # exit code 42
syscall             # call syscall
