.intel_syntax noprefix
jmp saut	# addr base
.rept 0x51      # 0x51 81*nop
nop
.endr
saut:
mov eax,1       # flow control
