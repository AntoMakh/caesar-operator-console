#!/bin/bash

usage() {
    echo "Usage: $0"
    echo "-h: open the help page"
    echo "-r: scan root directory"
    echo "-g: gtfo check"
    echo "-o <filename>: save output to file in directory of your choice (example: -o /home/user/scan_results.txt)"
}

dir=$(pwd)

while getopts 'hrgo:' flag; do
    case "$flag" in
        h) usage ;;
        r) dir="/" ;;
        g) gtfo_check=true ;;
        o) filename="$OPTARG" ; save=true ;;
        *) usage ;;
    esac
done

run_scan() {
    result=$(find "$dir" -type f -a \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
}

save_to_file() {
    echo "$result" > "$filename"
}

echo "Starting scan in directory: $dir"
run_scan
if [ "$save" = true ]; then
    save_to_file
else
    echo "$result"
fi

printed_gtfo=false

online_gtfo_check() {
    file_path="$1"
    name="${file_path##*/}" # only take binary name
    url="https://gtfobins.github.io/gtfobins/${name}/"
    if command -v curl > /dev/null 2>&1; then
        if curl -sL --max-time 5 "$url" | grep -qi 'id="[^"]*-suid"'; then
            echo "GTFOBins entry found for $name: $url"
            printed_gtfo=true
        fi
    elif command -v wget > /dev/null 2>&1; then
        if wget -qO- --timeout=5 "$url" | grep -qi 'id="[^"]*-suid"'; then
            echo "GTFOBins entry found for $name: $url"
            printed_gtfo=true
        fi
    else
        echo "Neither curl nor wget is available to check GTFOBins."
    fi
}

if [ "$gtfo_check" = true ]; then
    while IFS= read -r file; do
        online_gtfo_check "$file"
    done <<< "$result"
    if [ "$printed_gtfo" = false ]; then
        echo "No GTFOBins entries found for the scanned binaries."
    fi
fi

echo "Scan complete."