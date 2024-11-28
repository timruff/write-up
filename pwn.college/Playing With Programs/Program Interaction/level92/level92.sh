mkfifo t1
mkfifo t2
echo "/challenge/run < t1 1>t2 &" > script.sh
echo "cat t2 " >> script.sh
echo mrpmbupo > t1 | bash script.sh 
rm script.sh
rm t1
rm t2 
