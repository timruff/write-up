mkfifo fifo
/challenge/run > fifo & 
cat fifo
rm fifo
