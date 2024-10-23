#!/bin/bash
# Mac scores file removal script.

# Define the list of files to check
FILES=(
    "crwd_zta_1_25.txt"
    "crwd_zta_26_50.txt"
    "crwd_zta_51_75.txt"
    "crwd_zta_76_100.txt"
)

# Iterate over each file and delete it if it exists
for FILE in "${FILES[@]}"; do
    if [[ -f "$FILE" ]]; then
        
        rm "$FILE"
        echo "Deleted $FILE"
    else
        echo "File $FILE does not exist."
    fi
done