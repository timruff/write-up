.intel_syntax noprefix
xor rbx,rbx 		  # reset to 0
cmp rdi,0x0 		  # if adress 0
je return   		  # go to return
loop:  			  # begin loop 
mov r10,rdi		  # move rdi for manipulate
cmp byte ptr [rdi], 0x00  # if null caract
je return                 # go return
cmp byte ptr [rdi], 0x5a  # if caract upper case (convert to lower)
ja incr			  # if lower just inc
mov dil,byte ptr [rdi]	  # get uppercase caract to dil
mov rax, 0x403000	  # get add function to rax
call rax	          # call function to convert lowercase
mov byte ptr [r10],al     # add result to r10
inc rbx			  # inc number of conversion
mov rdi,r10		  # add r10 to rdi
incr:
inc rdi			  # inc offset adresse
jmp loop		  # next caractere
return:	
mov rax,rbx		  # mov result to rax
ret   			  # retrun result	
