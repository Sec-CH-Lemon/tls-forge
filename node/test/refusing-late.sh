#!/bin/sh
# A transport that refuses its arguments as pflag does, with code 2, its input
# closed first and its exit a moment after: a line longer than a pipe holds
# finds the pipe gone (EPIPE) before the client is told the process exited, as
# a refusing one's was, now and then, on a loaded runner (2026-11-09). A shell
# closes fd 0 and nothing else.
exec 0<&-
sleep 0.1
exit 2
