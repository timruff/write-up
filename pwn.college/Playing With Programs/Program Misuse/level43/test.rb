f = File.open("/flag","r")
f.each_line do |line|
    puts line
end
f.close
