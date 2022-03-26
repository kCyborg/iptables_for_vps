# iptables_for_vps

The idea behind this script is to apply some intereting iptables rules for our ETCESA's VPSs.

The script is for go alongside with <<<ARTICLE'S LINK>>>
You should know what TCP and UDP ports you want to open, write them in the respective variable
following the next sintax: port1,port2,port3:port15, don't let spaces between ports, if you 
wanna allow a range put the first port followed by : and the second port WITHOUT spaces

TCP_PORTS=port1,port2,port3:port15
TCP_PORTS=60100:62000

The script will check if the iptables-persistent is installed, if not  it will install it. 
It will make a copy of the /etc/iptables/rules.v4 in case the package is installed and there are 
rules applied, in /etc/iptables/rules.v4.bk

The rules allow the ports selected in the $TCP_PORTS and $UDP_PORTS variables, it also allow ping
and traceroute. Those IPs disallowed to access the VPS will be enter in a ban list and will be not 
allowed to access again in the next 20 seconds.

The rules will allow traffic from [cuban public IPs](https://www.nirsoft.net/countryip/cu.html), not from other countries.

ToDo list:
- Add a ban log view to see those sneaky bots trying to get under our skirt.
- Fix the range ports which is not working right now as intended
- Add some colors
