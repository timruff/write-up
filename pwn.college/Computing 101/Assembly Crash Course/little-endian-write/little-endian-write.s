.intel_syntax noprefix
movabs rax, 0xdeadbeef00001337
mov qword ptr [rdi], rax
movabs rax, 0xc0ffee0000
mov qword ptr [rsi], rax
