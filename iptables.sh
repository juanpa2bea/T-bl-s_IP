#!/bin/sh


IPT="/sbin/iptables" # Definition Iptable's path

# Network Interface defnition ==> ethernet interface
interface=wlp3s0

start() {
	
    ### Delete all the entries ###
    $IPT -F
    $IPT -X
    
    ### BLOCK ALL BY DEFAULT ###
    $IPT -P INPUT DROP
    $IPT -P OUTPUT DROP
    $IPT -P FORWARD DROP

    # Enable free use of loopback interfaces
    $IPT -A INPUT -i lo -j ACCEPT
    $IPT -A OUTPUT -o lo -j ACCEPT

    ###############
    ###    INPUT    ###
    ###############

    # === anti scan ===
    $IPT -N SCANS
    $IPT -A SCANS -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
    $IPT -A SCANS -p tcp --tcp-flags ALL ALL -j DROP
    $IPT -A SCANS -p tcp --tcp-flags ALL NONE -j DROP
    $IPT -A SCANS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ####################

    echo "The chain Anti-scan has been set"

    #No spoofing
    if [ -e /proc/sys/net/ipv4/conf/all/ip_filter ] ;
    then
    for filtre in /proc/sys/net/ipv4/conf/*/rp_filter
    do
    echo > 1 $filtre
    done
    fi
    echo "[Anti-spoofing is ready]"

    #No synflood
    if [ -e /proc/sys/net/ipv4/tcp_syncookies ] ;
    then
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    fi
    echo "[Anti-synflood is ready]"

    # TCP Syn Flood
    $IPT -A INPUT -i $interface -p tcp --syn -m limit --limit 3/s -j ACCEPT
    # UDP Syn Flood
    $IPT -A INPUT -i $interface -p udp -m limit --limit 10/s -j ACCEPT
    # Ping Flood
    $IPT -A INPUT -i $interface -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
    $IPT -A INPUT -i $interface -p icmp --icmp-type echo-reply -m limit --limit 1/s -j ACCEPT
    #
    echo "TCP, UDP, ICMP Flood is now limited!"

    ##############

    # Accept inbound TCP packets
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    #$IPT -A INPUT -p tcp --dport 21 -m state --state NEW -s 0.0.0.0/0 -j ACCEPT
    #$IPT -A INPUT -p tcp --dport 22 -m state --state NEW -s 0.0.0.0/0 -j AC$
    #$IPT -A INPUT -p tcp --dport 25 -m state --state NEW -s 0.0.0.0/0 -j ACCEPT
    $IPT -A INPUT -p tcp --dport 80 -m state --state NEW -s 0.0.0.0/0 -j ACCEPT
    #$IPT -A INPUT -p tcp --dport 110 -m state --state NEW -s 0.0.0.0/0 -j ACCEPT

    # Accept inbound UDP packets
    #$IPT -A INPUT -p udp -m udp --dport 123 -s 0.0.0.0/0 -j ACCEPT
    #$IPT -A INPUT -p udp -m udp --dport 67 -s 0.0.0.0/0 -j ACCEPT
    #$IPT -A INPUT -p udp -m udp --dport 53 -s 0.0.0.0/0 -j ACCEPT

    ####################
    ###    OUTPUT    ###
    ####################

    # == We do accept some protocols ==
    # $IPT -A OUTPUT -o $interface -p UDP --dport 123 -j ACCEPT        # Port 123  (Time ntp udp)
    #$IPT -A OUTPUT -o $interface -p TCP --dport 123 -j ACCEPT        # Port 123  (Time ntp tcp)
    $IPT -A OUTPUT -o $interface -p UDP --dport domain -j ACCEPT        # Port 53   (DNS)
    $IPT -A OUTPUT -o $interface -p TCP --dport domain -j ACCEPT        # Port 53   (DNS)
    $IPT -A OUTPUT -o $interface -p TCP --dport http -j ACCEPT        # Port 80   (Http)
    $IPT -A OUTPUT -o $interface -p TCP --dport https -j ACCEPT        # Port 443  (Https)
    $IPT -A OUTPUT -o $interface -p TCP --dport ssh -j ACCEPT            # Port 22 (SSH)
    #$IPT -t filter -A OUTPUT -o $interface -m state --state NEW -s $serveur -d $UPNP_Broadcast -p udp --sport 1024: --dport $SSDP_port -j ACCEPT   # broadcast UPNP for ushare
    # Generic OUTPUT
    $IPT -A OUTPUT -o $interface --match state --state ESTABLISHED,RELATED -j ACCEPT

    echo "############ <START> ##############"
    $IPT -L -n  # comment to deactivate printing of the current rules
    echo "############ </START> ##############"
}

stop() {
 ### OPEN ALL !!! ###
    $IPT -F
    $IPT -X
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    echo "############ <STOP> ##############"
    $IPT -L -n  # comment to deactivate printing of the current rules
    echo "############ </STOP> ##############"
 }

case "$1" in
  start)
    start
    ;;
  stop)
       stop
    ;;
  restart)
    stop
    start
    ;;
  *)
    N=/etc/init.d/${0##*/}
    echo "Usage: $N {start|stop|restart}" >&2
    exit 1
    ;;
esac

exit 0
