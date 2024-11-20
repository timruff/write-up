mov rdi,[rax]   # deference memory at rax to rdi 
mov rax,60      # number syscall exit
syscall         # call syscall
