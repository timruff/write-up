mov rax,1           # number syscall write
mov rdi, 1          # fd 1 standard output
mov rsi, 1337000    # first adresse of string
mov rdx, 1          # one letter
syscall             # call syscall
