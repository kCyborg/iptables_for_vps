#!/bin/bash

#####################################################################################################
### Readme section
# The script is for go alongside with <<<ARTICLE'S LINK>>>
# You should know what TCP and UDP ports you want to open, write them in the respective variable
# following the next sintax: port1,port2,port3:port15, don't let spaces between ports, if you 
# wanna allow a range put the first port followed by : and the second port WITHOUT spaces
#
# TCP_PORTS=port1,port2,port3:port15
# TCP_PORTS=60100:62000
#
# The script will check if the iptables-persistent is installed, if not  it will install it. 
# It will make a copy of the /etc/iptables/rules.v4 in case the package is installed and there are 
# rules applied, in /etc/iptables/rules.v4.bk
#
# The rules allow the ports selected in the $TCP_PORTS and $UDP_PORTS variables, it also allow ping
# and traceroute. Those IPs disallowed to access the VPS will be enter in a ban list and will be not 
# allowed to access again in the next 20 seconds.
#####################################################################################################


# User variables section
#TCP_PORTS=22,23,8888,64738
TCP_PORTS=22,23,80,443,543,64738
UDP_PORTS=64738
UDP_PORTS1=60001:60999


# Fixed variables section
HOSTIP=`curl ident.me`
NIC=ens192
OPENVP_NIC=tun0
OPENVP_SUBNET=10.8.0.0


# Check if iptables-persistent package is already installed
REQUIRED_PKG="iptables-persistent"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "No $REQUIRED_PKG. Setting up $REQUIRED_PKG."
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
  sudo apt --yes install $REQUIRED_PKG 
fi

if [ -f /etc/iptables/rules.v4 ]; then
  mv /etc/iptables/rules.v4 /etc/iptables/rules.v4.bk
fi

# Send the rules
cat > /etc/iptables/rules.v4 <<EOF
#=====
# RAW
#=====

*raw
:PREROUTING ACCEPT [0:0]
:LOG_BAN - [0:0]
#==================== PREROUTING RULES
# Descartar cualquier paquete futuro de una IP que haya sido puesta en lista negra temporal (20 segundos)
-A PREROUTING -m recent --update --seconds 20 --hitcount 1 --rttl --name banned -j LOG_BAN

# Descartar el PING para interfaz publica
#-A PREROUTING -i $NIC -p icmp --icmp-type echo-request -j LOG_BAN

# Mitigar flood ICMP
-A PREROUTING -p icmp --icmp-type echo-request -m length ! --length 0:128 -j LOG_BAN
-A PREROUTING -p icmp --icmp-type echo-request -m hashlimit --hashlimit-mode srcip --hashlimit-above 4/minute --hashlimit-burst 4 --hashlimit-name lim_ping -j LOG_BAN

# Paquetes TCP modificados
-A PREROUTING -p tcp --tcp-flags ALL ALL -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags ALL NONE -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags SYN,PSH SYN,PSH -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags SYN,URG SYN,URG -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags ACK,RST RST -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j LOG_BAN
-A PREROUTING -p tcp --tcp-flags ACK,URG URG -j LOG_BAN

# Descartar las nuevas conexiones TCP que no sean para 
# SSH, MTPROTO, SHAPESHIFTER, MOSH, Mumble
-A PREROUTING ! -i lo -p tcp -m tcp --syn -m multiport ! --dports $TCP_PORTS -j LOG_BAN
#==================== END PREROUTING RULES

#==================== LOG_BAN RULES
# Exclusiones del BAN
-A LOG_BAN -i $NIC -s $HOSTIP -j RETURN
-A LOG_BAN -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j RETURN

# Prefijo "BAN_raw" para todos los paquetes que entren a esta cadena
-A LOG_BAN -j NFLOG --nflog-prefix BAN_raw

# Denegar paquete que ya estaba en lista negra temporal
-A LOG_BAN -j DROP

# Retorno a la cadena principal
-A LOG_BAN -j RETURN
#==================== END LOG_BAN RULES
COMMIT

#========
# MANGLE
#========

*mangle
:PREROUTING ACCEPT [0:0]
:LOG_BAN - [0:0]
#==================== PREROUTING RULES
# Saltar a cadena "LOG_BAN" las conexiones invalidas
-A PREROUTING -m conntrack --ctstate INVALID -j LOG_BAN

# Saltar a la cadena "LOG_BAN" las nuevas conexiones TCP que no sean para
# SSH, MTPROTO, SHAPESHIFTER, MOSH, Mumble
-A PREROUTING -m conntrack --ctstate NEW ! -i lo -p tcp -m tcp -m multiport ! --dports $TCP_PORTS -j LOG_BAN

# Saltar a la cadena "LOG_BAN" las nuevas conexiones UDP que no sea Mumble
-A PREROUTING -m conntrack --ctstate NEW ! -i lo -p udp -m udp ! --dport $UDP_PORTS -j LOG_BAN
-A PREROUTING -m conntrack --ctstate NEW ! -i lo -p udp -m udp ! --dport $UDP_PORTS1 -j LOG_BAN

# Saltar a la cadena "LOG_BAN" las nuevas conexiones ICMP que no sean PING
-A PREROUTING -m conntrack --ctstate NEW ! -i lo -p icmp -m icmp ! --icmp-type echo-request -j LOG_BAN
#==================== END PREROUTING RULES

#==================== LOG_BAN RULES
# Exclusiones del BAN
-A LOG_BAN -i lo -j RETURN
-A LOG_BAN -i $NIC -s $HOSTIP -j RETURN
-A LOG_BAN -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j RETURN
# Permitir el traceroute
-A LOG_BAN -m conntrack --ctstate NEW ! -i lo -p udp -m udp --dport 33434:33534 -j RETURN

# Prefijo "BAN_mangle" para todos los paquetes que entren a esta cadena
-A LOG_BAN -j NFLOG --nflog-prefix BAN_mangle

# Denegar paquete y poner en lista negra
-A LOG_BAN -m recent --set --name banned -j DROP

# Retorno a la cadena principal
-A LOG_BAN -j RETURN
#==================== END LOG_BAN RULES
COMMIT

#========
# FILTER
#========

*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOG_DROP - [0:0]
:LOG_REJECT - [0:0]
:LOG_ACCEPT - [0:0]
#==================== INPUT RULES
# Aceptar todo del localhost
-A INPUT -i lo -j ACCEPT

# Aceptar las conexiones relacionadas o establecidas
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Aceptar las nuevas conexiones para TCP desde los rangos de IPs nacionales
# SSH, MTPROTO, SHAPESHIFTER, MOSH, Mumble
-A INPUT -m conntrack --ctstate NEW -s 152.206.0.0/15 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 169.158.0.0/16 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 181.225.224.0/19 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 190.6.64.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 190.6.80.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 190.15.144.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 190.92.112.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 190.107.0.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 196.1.112.0/24 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 196.1.135.0/24 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 196.3.152.0/24 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.0.16.0/24 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.0.24.0/22 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.5.12.0/22 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.13.144.0/21 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.14.48.0/21 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.55.128.0/19 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.55.160.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 200.55.176.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 201.220.192.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -s 201.220.208.0/20 -p tcp -m tcp -m multiport --dports $TCP_PORTS -j LOG_ACCEPT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones, para TCP Mumble
-A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --dport $UDP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --dport $UDP_PORTS1 -j LOG_ACCEPT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones, para UDP Mumble
-A INPUT -m conntrack --ctstate NEW -p udp -m udp --dport $UDP_PORTS -j LOG_ACCEPT
-A INPUT -m conntrack --ctstate NEW -p udp -m udp --dport $UDP_PORTS1 -j LOG_ACCEPT

# Saltar a la cadena "LOG_REJECT" las nuevas conexiones UDP que utiliza TRACEROUTE 
# para calcular los tiempos (no se neceitan abrir dichos puertos para averiguar los tiempos)
-A INPUT -m conntrack --ctstate NEW -p udp -m udp --dport 33434:33534 -j LOG_REJECT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones para todo
-A INPUT -m conntrack --ctstate NEW -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j LOG_ACCEPT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones ICPM para PING
-A INPUT -m conntrack --ctstate NEW -p icmp -m icmp --icmp-type echo-request -j LOG_ACCEPT

# Saltar a la cadena "LOG_DROP" el resto de las nuevas conexiones que seran denegadas por la regla por defecto
-A INPUT -m conntrack --ctstate NEW -j LOG_DROP
#==================== END INPUT RULES

#==================== FORWARD RULES
# Aceptar las conexiones relacionadas o establecidas
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones para todo
-A FORWARD -m conntrack --ctstate NEW -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j LOG_ACCEPT

# Saltar a la cadena "LOG_ACCEPT" las nuevas conexiones ICPM para PING
-A FORWARD -m conntrack --ctstate NEW -p icmp -m icmp --icmp-type echo-request -j LOG_ACCEPT

# Saltar a la cadena "LOG_DROP" el resto de las nuevas conexiones que seran denegadas por la regla por defecto
-A FORWARD -m conntrack --ctstate NEW -j LOG_DROP
#==================== END FORWARD RULES

#==================== LOG_DROP RULES
# Exclusiones del BAN
-A LOG_DROP -i lo -j RETURN
-A LOG_DROP -i $NIC -s $HOSTIP -j RETURN
-A LOG_DROP -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j RETURN

# Prefijo "BAN_filter" para todos los paquetes que entren a esta cadena
-A LOG_DROP -j NFLOG --nflog-prefix BAN_filter

# Denegar paquete
-A LOG_DROP -j DROP

# Retorno a la cadena principal
-A LOG_DROP -j RETURN
#==================== END LOG_DROP RULES

#==================== LOG_REJECT RULES
# Exclusiones del BAN
-A LOG_REJECT -i lo -j RETURN
-A LOG_REJECT -i $NIC -s $HOSTIP -j RETURN
-A LOG_REJECT -i $OPENVP_NIC -s $OPENVP_SUBNET/24 -j RETURN

# Prefijo "BAN_filter" para todos los paquetes que entren a esta cadena
-A LOG_REJECT -j NFLOG --nflog-prefix BAN_filter

# Rechazar paquete
-A LOG_REJECT -j REJECT

# Retorno a la cadena principal
-A LOG_REJECT -j RETURN
#==================== END LOG_REJECT RULES

#==================== LOG_ACCEPT RULES
# Prefijo "ACCEPT" para todos los paquetes que entren a esta cadena
-A LOG_ACCEPT -j NFLOG --nflog-prefix ACCEPT

# Aceptar paquete
-A LOG_ACCEPT -j ACCEPT

# Retorno a la cadena principal
-A LOG_ACCEPT -j RETURN
#==================== END LOG_ACCEPT RULES
COMMIT
EOF

echo "Rules writen"

# Apply the rules
iptables-apply /etc/iptables/rules.v4


