#!/bin/bash

# Define the file path
file_path="/home/xave/Scrivania/Prova/prova.txt"

# Define the content to write
content="Hello, world!"

# Define the number of iterations
iterations=100

# Loop to write to the file
for ((i=1; i<=$iterations; i++)); do
    # Write content to the file
    echo "$i"
    echo "$content $i" >> "$file_path"
    # Add a small delay (optional)
    sleep 0.2
done

echo "Writing complete!"
