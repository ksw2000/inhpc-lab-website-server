#!/bin/bash
export PATH=$PATH:/usr/local/go/bin
go build main.go

string=`ps -ef | grep "./main" | grep -v "grep" | tr -s " " | cut -d " " -f 2`
array=(${string//,/ })

for var in ${array[@]}
do
   sudo kill -9 $var
done

ulimit -n 1048576

nohup sudo ./main -p 443 &
echo $! > pid.txt