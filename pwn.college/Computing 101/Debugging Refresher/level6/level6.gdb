start
catch syscall read
commands
  silent
  if ($edx == 0x8)
    set $rip = *main+720
end
continue
