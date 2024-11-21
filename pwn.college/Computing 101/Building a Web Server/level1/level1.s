.intel_syntax noprefix
.globl _start

.section .text

_start:
	mov rdi,0	# error code 0 is good
	mov rax,60	# number syscall exit
	syscall		# call syscall

.section .data
