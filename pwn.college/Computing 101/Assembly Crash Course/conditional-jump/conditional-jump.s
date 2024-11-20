.intel_syntax noprefix
mov ebx,[rdi]		# add content at adress to ebx
mov eax, [rdi+4]	# it's same for all
cmp rbx, 0x7f454c46     
jne stepA		# if not good value to go next step
add eax, [rdi+8]
add eax, [rdi+12]
jmp done
stepA:
cmp rbx, 0x0005a4d      # if not good value to go next step
jne other
sub eax, [rdi+8]
sub eax, [rdi+12]
jmp done
other:			# else
imul eax, [rdi+8]
imul eax, [rdi+12]
done:
