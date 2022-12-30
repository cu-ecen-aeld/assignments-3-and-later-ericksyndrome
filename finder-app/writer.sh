#!/bin/bash

#first two arguements that will be accepted

writefile=$1
writestr=$2

if [ $# != 2 ]  #checks that two arguements were provided
then
	echo "arguements not specified"
	exit 1 
fi

#create the directory 
writedir=$(dirname $writefile)
mkdir -p $writedir

#overwrite the file with writestr
echo $writestr > $writefile


