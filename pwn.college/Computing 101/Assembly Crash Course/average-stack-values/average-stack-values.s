.intel_syntax noprefix
mov rbx, 4		# diviseur
mov rax, qword ptr [rsp]
add rax, qword ptr [rsp+8]
add rax, qword ptr [rsp+16]
add rax, qword ptr [rsp+24]
div rbx			# rax/rbx
push rax
