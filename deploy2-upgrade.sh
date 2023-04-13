#!/bin/bash

##############################################################
echo '===Opening up IPTables to allow intenet comms========='
rm /etc/iptables/rules.v4
echo '*filter' >> /etc/iptables/rules.v4
echo ':INPUT DROP [130:14631]' >> /etc/iptables/rules.v4
echo ':FORWARD DROP [0:0]' >> /etc/iptables/rules.v4
echo ':OUTPUT ACCEPT [0:0]' >> /etc/iptables/rules.v4
echo '#Allow loopback reverse telnet for Ser2Net connections' >> /etc/iptables/rules.v4
echo '-A INPUT -i lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A OUTPUT -o lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '#Allow secured/whitelisted IPs on custom SSH port' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.6.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.32.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.3.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '#The following two entires are only enabled for OS updates during scheduled CRON' >> /etc/iptables/rules.v4
echo '-A INPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A OUTPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '#Drop everything else during normal operations' >> /etc/iptables/rules.v4
echo '#-A INPUT -j DROP' >> /etc/iptables/rules.v4
echo 'COMMIT' >> /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
echo '###DONE!###'
##############################################################
echo '===Performing update and system upgrades==============='
sudo apt-get update
sudo apt-get upgrade -y
echo '###DONE!###'
##############################################################
echo '===Re-instating Hardened IPtables======================'
rm /etc/iptables/rules.v4
echo '*filter' >> /etc/iptables/rules.v4
echo ':INPUT DROP [130:14631]' >> /etc/iptables/rules.v4
echo ':FORWARD DROP [0:0]' >> /etc/iptables/rules.v4
echo ':OUTPUT ACCEPT [0:0]' >> /etc/iptables/rules.v4
echo '#Allow loopback reverse telnet for Ser2Net connections' >> /etc/iptables/rules.v4
echo '-A INPUT -i lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A OUTPUT -o lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '#Allow secured/whitelisted IPs on custom SSH port' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.6.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.32.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A INPUT -s 10.3.88.120/32 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '#The following two entires are only enabled for OS updates during scheduled CRON' >> /etc/iptables/rules.v4
echo '#-A INPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '#-A OUTPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '#Drop everything else during normal operations' >> /etc/iptables/rules.v4
echo '-A INPUT -j DROP' >> /etc/iptables/rules.v4
echo 'COMMIT' >> /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
echo '###DONE!###'
