.intel_syntax noprefix
xor rax,rax # reset 0 store no null byte
cmp rdi,0x0 # check rdi value
je done     # if 0 go end
loop: 	    # begin loop
mov bl, byte ptr [rdi+rax] # get byte 
cmp bl,0x0  # check byte
je done	    # if 0 go end
inc rax	    # inc no null caract
jmp loop    # check next bytes
done:       # end
