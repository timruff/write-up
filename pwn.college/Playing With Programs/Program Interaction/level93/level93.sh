mkfifo t1
mkfifo t2
/challenge/run < t1 > t2 &
cat < t2 &
cat > t1
rm t1 t2
