#!/bin/bash

output="combined.txt"
root="."

# Empty or create the output file
> "$output"

find "$root" \
  -type d \( -name ".venv" -o -name "__pycache__" \) -prune -false \
  -o -type f \
     \( -name "*.py" -o -name "*.html" -o -name "*.css" -o -name "*.sql" -o -name "README.md" -o -name "requirements.txt" \) \
     ! -name "$output" \
  | sort | while read -r file; do
      echo "===== $file =====" >> "$output"
      cat "$file" >> "$output"
      echo -e "\n" >> "$output"
done

