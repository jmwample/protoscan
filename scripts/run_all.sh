#!/usr/bin/bash


if [[ "$EUID" != 0 ]]; then
    sudo -k # make sure to ask for password on next sudo
    if sudo false; then
        echo "incorrect password"
        exit 1
    fi
fi

echo "starting at `date '+%X %N'`"

bidipath="./"
BIDI="${bidipath}/bidi"

workers="2000"
delay="10ms"
iface="enp1s0f0"
laddr=""
laddr6=""
domains="${bidipath}/domainlist.txt"
ips="${bidipath}/iplist.txt"
outpath="${bidipath}/out/"


# run TLS
echo "starting TLS  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type tls -d "${outpath}/cn/tls"
echo "finished TLS  `date '+%X %N'`"
sleep 180

# run TLS NSA
echo "starting TLS-NSA  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type tls -nsa -d "${outpath}/cn/tls-nsa"
echo "finished TLS-NSA  `date '+%X %N'`"
sleep 180

# run HTTP
echo "starting HTTP  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type http -d "${outpath}/cn/http/"
echo "finished HTTP  `date '+%X %N'`"

sleep 180

# run HTTP NSA
echo "starting HTTP-NSA  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type http -nsa -d "${outpath}/cn/http-nsa"
echo "finished HTTP-NSA  `date '+%X %N'`"
sleep 180

# run Quic
echo "starting Quic  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type quic -d "${outpath}/cn/quic"
echo "finished Quic  `date '+%X %N'`"
sleep 180

# run DNS A
echo "starting DNS A  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type dns -d "${outpath}/cn/dns-A"
echo "finished DNS A  `date '+%X %N'`"
sleep 180

# run DNS AAAA
echo "starting DNS AAAA  `date '+%X %N'`"
cat $ips | shuf |  zblocklist -b /etc/zmap/blacklist.conf  | sudo $BIDI -ips $ips -domains $domains -iface $iface -wait $delay -laddr $laddr -laddr6 $laddr6 -workers $workers -type dns -qtype 28 -d "${outpath}/cn/dns-AAAA"
echo "finished DNS AAAA  `date '+%X %N'`"
sleep 5

echo "finised at `date '+%X %N'`"
