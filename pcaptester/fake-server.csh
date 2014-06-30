#!/bin/csh
printf "HTTP/1.1 200 OK\r\n"
printf "Content-Type: text/html\r\n"
printf "Content-Length: %d\r\n\r\n" $1
base64 /dev/urandom |head -c $1

