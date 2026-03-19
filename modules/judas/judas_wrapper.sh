#! /bin/bash

host="$1"
port="$2"
file="$3"
keyword="$4"
scheme="$5"

address="$host:$port"
script_dir="$(cd "$(dirname "$0")" && pwd)"
if [ -n "$scheme" ]; then
    "$script_dir/judas.sh" -f "$file" -k "$keyword" -s "$scheme" "$address"
else
    "$script_dir/judas.sh" -f "$file" -k "$keyword" "$address"
fi
