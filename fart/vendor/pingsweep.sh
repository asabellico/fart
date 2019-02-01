#!/bin/bash

# requirements: apt install prips

ip_range=$1
if [ -z $ip_range ]; 
then
	echo 'usage: '$0' <cidr>'
	exit 0
fi

prips $ip_range | xargs -P10 -I% sh -c "ping -c1 -W1 % >/dev/null && echo %' responds to ICMP ping request'"

return 0