#! /bin/bash

# WRITTEN BY
#  ________
# /        \
# | b1smrk |
# \________/
#                                      |__
#                                      |\/
#                                      ---
#                                      / | [
#                               !      | |||
#                             _/|     _/|-++'
#                         +  +--|    |--|--|_ |-
#                      { /|__|  |/\__|  |--- |||__/
#                     +---------------___[}-_===_.'____                 /\
#                 ____`-' ||___-{]_| _[}-  |     |_[___\==--            \/   _
#  __..._____--==/___]_|__|_____________________________[___\==--____,------' .7
# |                                                                          /
#  \_________________________________________________________________________|

usage() {
    echo "Usage: $0 <domain_name>"
    echo "-h: open the help page"
    exit 1
}

while getopts 'h' flag; do
        case "$flag" in
        h) usage ;;
        *) usage ;;
        esac
done

if [ -z "$1" ]; then
    usage
    exit 1
fi

domain="$1"

dns=$(host -t ns "$domain" | cut -d ' ' -f 4)
record_pattern="has address|has IPv6 address|name server|mail is handled by"
for server in $dns; do
    answer=$(host -l "$domain" "$server" 2>&1)
    status=$?
    records=$(echo "$answer" | grep -E "$record_pattern")

    # A transfer only succeeded if host exited cleanly and returned zone records.
    # Anything else (timeout, "Transfer failed", connection errors) is a failure,
    # not a success, even when the output does not contain the word "refused".
    if [ "$status" -eq 0 ] && [ -n "$records" ]; then
        echo "Zone transfer successful with $server"
        echo "$records"
    elif echo "$answer" | grep -q "REFUSED"; then
        echo "Zone transfer refused by $server"
    else
        echo "Zone transfer failed against $server"
        echo "$answer" >&2
    fi
done