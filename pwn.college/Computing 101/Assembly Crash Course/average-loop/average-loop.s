.intel_syntax noprefix
xor rcx,rcx	    # initialise 0
xor rbx,rbx  	    # initialise 0
loop:
cmp rbx, rsi	    # comparator
je average	    # if ok div
add rcx,[rdi+rbx*8] # add all number
inc rbx 	    # inc for loop
jmp loop	    # loop
average:
xor rdx,rdx	    # initialise 0
mov rax, rcx 	    # quotient
mov rcx, rsi        # divisor
div rcx		    # calcul
