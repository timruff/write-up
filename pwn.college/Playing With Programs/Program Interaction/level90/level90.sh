mkfifo fifo
echo "/challenge/run < fifo" > script.sh
echo bnswyafr > fifo | bash script.sh
rm script.sh
rm fifo
