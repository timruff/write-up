mkfifo stdin
echo gtvsnhcs > pass
exec 18< pass
/challenge/run <& 18
rm pass
rm stdin
