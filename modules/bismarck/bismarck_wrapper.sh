#! /bin/bash

target="$1"
port="$2"
script_dir="$(cd "$(dirname "$0")" && pwd)"
if [ -n "$port" ]; then
    "$script_dir/bismarck.sh" -p "$port" "$target"
else
    "$script_dir/bismarck.sh" "$target"
fi