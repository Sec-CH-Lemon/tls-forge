#!/bin/sh
# A transport that answers once and then stops reading, without dying.
#
# The client's write callback exists for the gap between "the process is alive"
# and "the bytes reached it", and that gap cannot be produced from Node: closing
# process.stdin leaves the descriptor open, so the pipe keeps a reader, and
# closing the descriptor under a live libuv handle takes the process down with
# a signal instead. A shell closes fd 0 and nothing else.
read -r line
id=$(printf '%s' "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
printf '{"id":%s,"status":200,"url":"https://deaf/first","body":"","headers":{},"cookies":[]}\n' "$id"
exec 0<&-
sleep 30
