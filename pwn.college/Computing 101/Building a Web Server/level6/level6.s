.intel_syntax noprefix
.globl _start

.section .rodata
	msg: .ascii "HTTP/1.0 200 OK\r\n\r\n\0"
.section .data
	buffer:		.space 1024
	socket_fd:	.quad 0
	accept_fd:	.quad 0
.section .text

_start:
	# socket()
	mov rdi,2	   # AF INET (web)
	mov rsi,1	   # SOCK_STREAM (TCP)
	mov rdx,0	   # IPPROTO_IP (Dummy protocol for TCP)
	mov rax,41	   # number syscall socket
	syscall		   # call syscall
	mov socket_fd,rax  # save socket_fd
	# bind()
	mov rdi,socket_fd  # fd 3
	# struct sockaddr_in ( argument reverse stack)
	mov DWORD PTR [rsp-0x4],0x0 # 0.0.0.0 address 32 bits
	mov WORD PTR [rsp-0x6],0x5000 # port 80 0x50 little endian 
	mov WORD PTR [rsp-0x8],0x2  # AF_INET (web)
	sub rsp,0x8 		    # go begin stack struck
	mov rdx,16 	   # size struct
	mov rsi,rsp	   # struct addr to rsi
	mov rax,49	   # number syscall bind
	syscall		   # call syscall
	# listen()
	mov rdi,socket_fd  # fd
	mov rsi,0          # backlog maximum queue pending
	mov rax,50	   # number syscall listen
	syscall		   # call syscall
	# accept()
	mov rdi,socket_fd  # fd
	mov rsi,0	   # sockaddr 
	mov rdx,0	   # socklen_t
	mov rax,43	   # number syscall accept
	syscall		   # call syscall
	mov accept_fd,rax  # take fd request accept
	# read()
	mov rdi,accept_fd  # fd
	lea rsi, buffer    # store data read
	mov rdx, 1024	   # size of store data
	mov rax,0	   # number syscall read
	syscall		   # call syscall
	# write()
	mov rdi,accept_fd  # fd
	lea rsi,msg        # load string by address  
	mov rdx,19	   # size of string
	mov rax,1	   # number syscall write 
	syscall		   # call syscall
	# close()
	mov rdi,accept_fd  # close fd
	mov rax,3	   # number syscall close
	syscall		   # call syscall
	# exit()
	mov rdi,0	   # error code 0 is good
	mov rax,60	   # number syscall exit
	syscall		   # call syscall
