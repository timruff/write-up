# MSB                  32        16    8   0   
# +----------------------------------------+
# |                   rax                  |
# +--------------------+-------------------+
#                      |        eax        |
#                      +---------+---------+
#                                |   ax    |
#                                +----+----+
#                                | ah | al |
#                                +----+----+
.intel_syntax noprefix
mov al,dil # dil 8 bit lsd and al
mov bx,si  # si 16 bit and bx 16 bit
