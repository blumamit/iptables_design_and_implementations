#!/bin/bash
PATH=/usr/sbin:/sbin:/usr/bin:/bin

###################################################################################
######						 Configuration section							#######
###################################################################################


# can be 5060 or 5744. Make sure /etc/asterisk/sip.conf is configured with same bindport.
port=5060

# true or false
openPort80ForAll=false

#Client Static IPs. add IP's between quotes ""
clientStaticIPsList=(

)

clientVPNIPsList=(

)

adminStaticIPsList=(
"212.179.241.172"
)

adminVPNIPsList=(
"192.241.250.141"
)

adminInstallServers=(

)

inboundGateways=(

)

# Spoofs. For cluster server - remove the IP range of the server's LAN from this list:
spoofIPs=(
"0.0.0.0/8"
"127.0.0.0/8"
"172.16.0.0/12"
"192.168.0.0/16"
"224.0.0.0/3"
"169.254.0.0/16"
)

# Number of Agents for the client (giveortake)
numOfAgents=5

#Change these settings only on clusters
isCluster=false

dbIP=(

)
asteriskIPlist=(

)SSH
webIP=(

)

iptablesSaveDirectory=/root/iptables
iptablesSaveFilename="iptables-$(date "+%Y.%m.%d-%H:%M:%S")"



#####################################################################################
#####		/Configuration. DO NOT TOUCH AFTER THIS COMMENT	!!!!				#####
#####################################################################################


# 1. Smart spoof prevension - Make sure that in /etc/sysctl.conf:
# net.ipv4.conf.all.rp_filter=1
# net.ipv4.conf.all.log_martians=1
# net.ipv4.conf.default.log_martians=1

# 2. DISABLE IPv6 - Make sure that in /etc/sysctl.conf:
# net.ipv6.conf.all.disable_ipv6 = 1

# 3. To stop slowloris attacks make sure to install apache qos mode
# /etc/apache2/mods-available/qos.conf

# 4. Apache hardening: Use mod_security and mod_evasive Modules. Hide file contents of directories by using Options -Indexes in httpd.conf.


# Temporarily change default policy to accept (to not get blocked out in SSH)
iptables -P INPUT ACCEPT
# Flush all rules, delete all non default chains.
iptables -t mangle -F
iptables -F
iptables -X


# LOOPBACK
iptables -A INPUT -i lo -m comment --comment "Loopback" -j ACCEPT
iptables -A OUTPUT -o lo -m comment --comment "Loopback" -j ACCEPT



# AUTOMATIC SCANNING TOOLS AND OTHER MALICIOUS PACKETS:
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate NEW -p tcp ! --syn -j REJECT --reject-with tcp-reset



# PREVENT SYNFLOOD FROM AUTOMATIC FLOODING TOOLS:
iptables -t mangle -A PREROUTING -p tcp -m multiport --dport 80,443 -m conntrack --ctstate NEW -m tcpmss ! --mss 500:65535 -m limit --limit 6/min -j LOG --log-prefix "Prevent Synflood " --log-level 6
iptables -t mangle -A PREROUTING -p tcp -m multiport --dport 80,443 -m conntrack --ctstate NEW -m tcpmss ! --mss 500:65535 -m comment --comment "Prevent Synflood" -j DROP




# ALLOW ICMP ECHO-REQUESTS
iptables -A INPUT -p icmp --icmp-type 8 -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type 8 -m limit --limit 1/s --limit-burst 3 -j ACCEPT



# ANTI SPOOFING
iptables -N ANTISPOOFING
serverIP=(`ifconfig | grep -A1 "Link encap:Ethernet" | grep -v "Link encap:Ethernet" | cut -d":" -f2 | cut -d" " -f1 | egrep '([1-2]?[0-9]{0,2}\.){3,3}[1-2]?[0-9]{0,2}'`)
for ip in "${spoofIPs[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "Spoofed IP" -j ANTISPOOFING
done
for ip in "${serverIP[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "Spoofed IP" -j ANTISPOOFING
done
iptables -A ANTISPOOFING -j LOG -m limit --limit 6/min --log-prefix "Spoofed IP detected: "
iptables -A ANTISPOOFING -j DROP



# ALLOW FULL ACCESS TO ADMIN, GATEWAYS AND CLUSTER SERVERS
iptables -N FULLACCESS

for ip in "${adminStaticIPsList[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "admin Office IP" -j FULLACCESS
done
for ip in "${adminVPNIPsList[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "admin VPN IP" -j FULLACCESS
done
for ip in "${adminInstallServers[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "admin Install Server IP" -j FULLACCESS
done
for ip in "${inboundGateways[@]}"
do
	iptables -A INPUT -s $ip -m comment --comment "admin Inbound Gateways" -j FULLACCESS
done
if [ "$isCluster" = true ]; then
	for ip in "${dbIP[@]}"
	do
		iptables -A INPUT -s $ip -m comment --comment "Cluster DB IP" -j FULLACCESS
	done
	for ip in "${asteriskIPlist[@]}"
	do
		iptables -A INPUT -s $ip -m comment --comment "Cluster Asterisk IP" -j FULLACCESS
	done
	for ip in "${webIP[@]}"
	do
		iptables -A INPUT -s $ip -m comment --comment "Cluster Webserver IP" -j FULLACCESS
	done
fi
iptables -A FULLACCESS -j ACCEPT



# ALLOW HTTP REQUESTS, THROTTLE DOWN TO PREVENT SYNFLOODS. Thruttle parameters can be changed according to number of agents behind NAT.
iptables -N WEBACCESS
if [ "$openPort80ForAll" = true ]; then
	iptables -A INPUT -p tcp --syn -m multiport --dports 80,443 -m hashlimit --hashlimit $((10*numOfAgents))/min --hashlimit-burst $((10*numOfAgents)) --hashlimit-mode srcip --hashlimit-name synthrottle -m comment --comment "Allow web access" -j WEBACCESS
else
	for ip in "${clientStaticIPsList[@]}"
	do
		iptables -A INPUT -s $ip -p tcp --syn -m multiport --dports 80,443 -m hashlimit --$((10*numOfAgents))/min --hashlimit-burst $((10*numOfAgents)) --hashlimit-mode srcip --hashlimit-name synthrottle -m comment --comment "Client IP web access" -j WEBACCESS
	done
	for ip in "${clientVPNIPsList[@]}"
	do
		iptables -A INPUT -s $ip -p tcp --syn -m multiport --dports 80,443 -m hashlimit --hashlimit $((10*numOfAgents))/min --hashlimit-burst $((10*numOfAgents)) --hashlimit-mode srcip --hashlimit-name synthrottle -m comment --comment "Allow VPN web access" -j WEBACCESS
	done
fi
iptables -A WEBACCESS -j ACCEPT


# Change back default policy to drop
iptables -P INPUT DROP


# Deny SIP DOS attacks scanners

iptables -N SIPDOSCHECK
iptables -N SIPDOSDROP
iptables -A INPUT -m comment --comment "Drop SIP DoS attacks" -j SIPDOSCHECK

iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "sundayddr" --algo bm --to 65535 -m comment --comment "Deny sundayddr" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "sipsak" --algo bm --to 65535 -m comment --comment "Deny sipsak" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "sipvicious" --algo bm --to 65535 -m comment --comment "Deny sipvicious" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "friendly-scanner" --algo bm --to 65535 -m comment --comment "Deny friendly-scanner" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "iWar" --algo bm --to 65535 -m comment --comment "Deny iWar" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "sip-scan" --algo bm --to 65535 -m comment --comment "Deny sip-scan" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "VaxSIPUserAgent" --algo bm --to 65535 -m comment --comment "Deny VaxSIP" -j SIPDOSDROP
iptables -A SIPDOSCHECK -p udp -m udp --dport $port -m string --string "sipcli" --algo bm --to 65535 -m comment --comment "Deny SipCLI" -j SIPDOSDROP

iptables -A SIPDOSDROP -m limit --limit 6/min -j LOG --log-prefix "firewall-sipdos: " --log-level 6
iptables -A SIPDOSDROP -j DROP


# Allow SIP on UDP port 5060/5744. Include SIP brute-force+DOS protections
iptables -N SIPTRAFFIC

iptables -A INPUT -p udp -m udp --dport $port -m comment --comment "Check legitimate SIP traffic" -j SIPTRAFFIC

iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "REGISTER sip:" --algo bm -m recent --update --seconds 60 --hitcount $((6*numOfAgents)) --name VOIPREG --rsource -m limit --limit 6/min -j LOG --log-prefix "SIP Reg BForce Detected: " --log-level 6
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "REGISTER sip:" --algo bm -m recent --update --seconds 60 --hitcount $((6*numOfAgents)) --name VOIPREG --rsource -j DROP
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "REGISTER sip:" --algo bm -m recent --set --name VOIPREG --rsource
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "INVITE sip:" --algo bm -m recent --update --seconds 60 --hitcount $((6*numOfAgents)) --name VOIPINV --rsource -m limit --limit 6/min -j LOG --log-prefix "SIP Inv flood Detected: " --log-level 6
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "INVITE sip:" --algo bm -m recent --update --seconds 60 --hitcount $((6*numOfAgents)) --name VOIPINV --rsource -j DROP
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -m string --string "INVITE sip:" --algo bm -m recent --set --name VOIPINV --rsource
iptables -A SIPTRAFFIC -p udp -m hashlimit --hashlimit 6/sec --hashlimit-mode srcip,dstport --hashlimit-name tunnel_limit -m udp --dport $port -j ACCEPT
iptables -A SIPTRAFFIC -p udp -m udp --dport $port -j DROP



# STATEFUL
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT



# RTP - the media stream
# (related to the port range in /etc/asterisk/rtp.conf) 
iptables -A INPUT -p udp -m udp --dport 10000:20000 -m comment --comment "Allow RTP" -j ACCEPT



# MGCP - if you use media gateway control protocol in your configuration
#iptables -A INPUT -p udp -m udp --dport 2727 -j ACCEPT


# SSH prevent bruteforce -> to be determined if needed as SSH access is very limited



# CLEANUP
iptables -N CLEANUP

iptables -A INPUT -j CLEANUP

iptables -A CLEANUP -p tcp --dport 22 -m limit --limit 6/min -j LOG --log-prefix "Unauth SSH detected: " --log-level 6
iptables -A CLEANUP -p udp -j REJECT --reject-with icmp-port-unreachable
iptables -A CLEANUP -p tcp -j REJECT --reject-with tcp-reset
iptables -A CLEANUP -j DROP



# Create iptables backup file.
mkdir -p $iptablesSaveDirectory
iptables-save >> $iptablesSaveDirectory/$iptablesSaveFilename.bak

/root/isIptablesUp.sh