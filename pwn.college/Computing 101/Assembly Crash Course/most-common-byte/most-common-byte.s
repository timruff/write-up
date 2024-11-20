.intel_syntax noprefix
# Argument System V AMD64 ABI (rdi,rsi,rdx,rcx,r8,r9)
push rbp 		# save rbp in stack
mov rbp,rsp		# base pointer
sub rsp,rsi		# allocate memory in stack
mov rax,-1		# begin loop add 1 for 0
sub rsi,1		# remove for test (size)
loop1:			# loop 1 for put nb o caractere in stack
add rax,1		# incremente 1
cmp rax,rsi		# compare size
jg next			# if greather go next
xor rcx,rcx		# initalise rcx to 0
mov cl,[rdi+rax]	# get curr_byte
mov r11,rbp		# put rbp in register for manipulation
sub r11,rcx		# stack_base-curr_byte
mov dl,[r11]		# move address to dl
add dl,1		# incremente 1
mov [r11],dl		# apply modification
jmp loop1		# next caracter
next:
xor rbx,rbx		# initialise to 0
xor rcx,rcx		# initialise to 0
mov ax,-1		# begin loop add 1 for 0
loop2: 			# loop 2 calculate more freq
add ax,1		# incr for next caractere
cmp ax,0xff		# compare all bytes 00 to ff
jg return		# si more exit to return result
mov r11,rbp		# put rbp in register for manipulation
sub r11,rax		# stack_base-b
mov dl,[r11]		# move address to dl
cmp dl,bl		# test max freq
jle loop2		# if less go next caractere
mov bl,dl		# else swap value max freq
mov cl,al		# byte more present
jmp loop2		# next caractere
return:
mov rax,rcx		# mov max_freq_byte to rax for return value
mov rsp,rbp		# restore rsp
pop rbp			# restore rbx
ret			# return value
