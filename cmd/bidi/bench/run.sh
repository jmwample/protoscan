#!/bin/bash

if [[ "$EUID" != 0 ]]; then
    sudo -k # make sure to ask for password on next sudo
    if sudo false; then
        echo "incorrect password"
        exit 1
    fi
fi


echo "starting at `date '+%X'`"

# create dummy interface with address
modprobe -v dummy numdummies=1
ip addr add 192.168.200.200/24 dev dummy0
ip link set dummy0 up

# printf "192.168.200.200" | ../bidi -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type tls -syn-delay=0s -wait 0s -d out-$i


# set iptables rules to prevent the kernel from responding to probe traffic ever
iptables -I INPUT -i lo -s 192.168.200.200 -j DROP

for i in 1 5 10 25 50 75 100 250 500 1000
do

    # # run TLS NSA
    # echo "starting TLS-NSA $i"
    # ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type tls -nsa -wait 0s -d out-$i/tls-nsa -verbose=false
    # sleep 5
    #
    # # run TLS
    # ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type tls -syn-delay=0s -wait 0s -d out-$i/tls
    # sleep 5
    #
    # # run HTTP
    # ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type http -syn-delay=0s -wait 0s -d out-$i
    # sleep 5
    #
    # # run HTTP NSA
    # ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type tls -nsa -wait 0s -d out-$i
    # sleep 5
    #
    # run Quic
    echo "starting Quic $i"
    ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type quic -wait 0s -d out-$i/quic -verbose=false
    sleep 5

    # run DNS
    echo "starting DNS $i"
    ../bidi -ips ips.local.1000 -domains domains.10000 -iface lo -laddr 192.168.200.200 -workers $i -type dns -wait 0s -d out-$i/dns -verbose=false
    sleep 5

done


# clear ip tables rules
iptables -D INPUT -i lo -s 192.168.200.200 -j DROP

# # delete dummy interface with address
ip link set dummy0 down
ip addr del 192.168.200.200/24 dev dummy0
rmmod dummy
