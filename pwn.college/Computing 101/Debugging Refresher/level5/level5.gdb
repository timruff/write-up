start
break *main+709
continue
    commands
    silent
    set $local_variable = *(unsigned long long*)($rbp-0x18)
    printf "%llx\n", $local_variable
    continue 
end
break *main+818
    commands
    silent
    set $rax=0x1337
    set $rdx=0x1337
    continue
end
break *main+837
    commands
    silent
    set *(unsigned long long*)($rbp-0x1c)=0x8
    continue
end
continue
