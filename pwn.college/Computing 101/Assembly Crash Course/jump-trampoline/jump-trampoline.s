.intel_syntax noprefix
jmp saut	# addr base
.rept 0x51      # 0x51 81*nop
nop
.endr
saut:
pop rdi
mov rax, 0x403000
jmp rax
