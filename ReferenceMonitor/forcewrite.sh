#!/bin/bash

output_file="/home/xave/Desktop/Prova/link.txt"

# Infinite loop
while true
do
    # Echo a message to the output file
    echo "Hello, world!" >> "$output_file"
    # Sleep for 1 second (adjust as needed)
    sleep 0.05
done
