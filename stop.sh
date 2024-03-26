#!/bin/bash
string=`ps -ef | grep "./main" | grep -v "grep" | tr -s " " | cut -d " " -f 2`
array=(${string//,/ })

for var in ${array[@]}
do
   sudo kill -9 $var
done