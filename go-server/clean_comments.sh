#!/bin/bash

DIR="${1:-.}"

find "$DIR" -name "*.go" -type f ! -name "clean_comments.sh" | while read -r file; do
    echo "Cleaning: $file"
    python3 -c "
import sys

def remove_comments(content):
    result = []
    in_string = False
    string_char = None
    i = 0
    
    while i < len(content):
        char = content[i]
        next_char = content[i+1] if i+1 < len(content) else None
        
        if not in_string:
            if char in ('\"', '\`', \"'\"):
                in_string = True
                string_char = char
                result.append(char)
            elif char == '/' and next_char == '/':
                break
            elif char == '/' and next_char == '*':
                i += 2
                while i < len(content):
                    if content[i] == '*' and i+1 < len(content) and content[i+1] == '/':
                        i += 2
                        break
                    i += 1
            else:
                result.append(char)
        else:
            result.append(char)
            if char == string_char and (i == 0 or content[i-1] != '\\\\'):
                in_string = False
                string_char = None
        i += 1
    
    return ''.join(result).rstrip()

with open('$file', 'r') as f:
    lines = f.readlines()

with open('$file', 'w') as f:
    for line in lines:
        cleaned = remove_comments(line)
        if cleaned.strip() or not line.strip():
            f.write(cleaned + '\n')
"
done

echo "Done"
