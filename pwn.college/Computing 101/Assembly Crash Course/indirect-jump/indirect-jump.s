.intel_syntax noprefix
cmp rdi, 3 	# test with 3
ja more		# if more 3 if other number
jmp [rsi+rdi*8] # jump to good adresse
more:		# else other cases
jmp [rsi+4*8]   # jump to good adresse
