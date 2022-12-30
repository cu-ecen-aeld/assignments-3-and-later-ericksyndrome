#!/bin/bash
#first scipt!


#need to exit with return val 1 if theres no path or string specified
filesdir=$1
searchstr=$2

if [ $# != 2 ]       
then
	echo "parameters not specified"
	exit 1
fi

#check and return exit value 1 if filesdir does not represent a directory


if [ ! -d $filesdir ]
then
	echo "Directory '$filesdir' does not exist."
	exit 1
fi

#print message with number of files and number of matching lines


num_files=$( ls "$filesdir" | wc -l )           
num_matches=$( grep -r "$searchstr" "$filesdir" | wc -l )

echo The number of files are $num_files and the number of matching lines are $num_matches

