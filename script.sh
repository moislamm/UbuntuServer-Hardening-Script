#!/bin/bash
##############################################################################################
echo '===Performing Update and Upgrade==='
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
echo '<<<Success>>>' 
##############################################################################################
echo '===Installing Applications========='
sudo DEBIAN_FRONTEND=noninteractive apt-get install ser2net nano iptables-persistent telnet rsyslog cron -y
echo '<<<Success>>>' 
##############################################################################################
echo '===Adding Cron job for auto maitenance==='
wget https://raw.githubusercontent.com/moislamm/linux-harden/main/upgrade.sh && chmod 700 upgrade.sh
echo "$(crontab -l ; echo '30 20 * * * /root/upgrade.sh') | crontab -"
##############################################################################################
echo '===Secureing SSH rules============='
rm /etc/hosts.allow
sudo touch /etc/hosts.allow
sudo chmod 600 /etc/hosts.allow
rm /etc/hosts.deny
sudo touch /etc/hosts.deny
sudo chmod 600 /etc/hosts.deny
echo "sshd: 192.168.0.0/16" >> /etc/hosts.allow
echo "shd: ALL" >> /etc/hosts.deny
echo '<<<Success>>>' 
##############################################################################################
echo '===Hardening SSH Application======='
rm /etc/ssh/sshd_config
touch /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
echo "Port 4044" >> /etc/ssh/sshd_config
echo "SyslogFacility AUTH" >> /etc/ssh/sshd_config
echo "LoginGraceTime 20" >> /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
echo "AllowAgentForwarding no" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
echo "PermitTunnel no" >> /etc/ssh/sshd_config
echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config
echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 180" >> /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "AllowUsers rwsadmin" >> /etc/ssh/sshd_config
echo "ChallengeResponseAuthentication no" >> /etc/ssh/sshd_config
echo "DebianBanner no" >> /etc/ssh/sshd_config
echo '<<<Success>>>' 
##############################################################################################
echo '===Hardening Kernel================'
rm /etc/sysctl.conf
touch /etc/sysctl.conf
chmod 600 /etc/sysctl.conf
echo "# Controls IP packet forwarding " >> /etc/sysctl.conf
echo "net.ipv4.ip_forward = 0 " >> /etc/sysctl.conf
echo "# Do not accept source routing " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0 " >> /etc/sysctl.conf
echo "# Controls the System Request debugging functionality of the kernel " >> /etc/sysctl.conf
echo "kernel.sysrq = 0 " >> /etc/sysctl.conf
echo "# Controls whether core dumps will append the PID to the core filename" >> /etc/sysctl.conf 
echo "# Useful for debugging multi-threaded applications " >> /etc/sysctl.conf
echo "kernel.core_uses_pid = 1 " >> /etc/sysctl.conf
echo "# Controls the use of TCP syncookies " >> /etc/sysctl.conf
echo "# Turn on SYN-flood protections " >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1 " >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 5 " >> /etc/sysctl.conf
echo "########## IPv4 networking start ##############" >> /etc/sysctl.conf
echo "# Send redirects, if router, but this is just server " >> /etc/sysctl.conf
echo "# So no routing allowed " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.send_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0 " >> /etc/sysctl.conf
echo "# Accept packets with SRR option? No " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_source_route = 0 " >> /etc/sysctl.conf
echo "# Accept Redirects? No, this is not router " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0 " >> /etc/sysctl.conf
echo "# Log packets with impossible addresses to kernel log? yes " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1 " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0 " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0 " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.secure_redirects = 0 " >> /etc/sysctl.conf
echo "# Ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast " >> /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1 " >> /etc/sysctl.conf
echo "# Prevent against the common syn flood attack " >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1 " >> /etc/sysctl.conf
echo "# Enable source validation by reversed path, as specified in RFC1812 " >> /etc/sysctl.conf
echo "net.ipv4.conf.all.rp_filter = 1 " >> /etc/sysctl.conf
echo "# Controls source route verification " >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1 " >> /etc/sysctl.conf
echo '<<<Success>>>' 
##############################################################################################
echo '===Disabling IPv6=================='
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/g' /etc/default/grub
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/g' /etc/default/grub
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/g' /etc/default/grub
sudo update-grub
echo '<<<Success>>>' 
##############################################################################################
echo '===Hardening IPTables=============='
rm /etc/iptables/rules.v4
sudo iptables-save > /etc/iptables/rules.v4
echo '*filter' >> /etc/iptables/rules.v4
echo ':INPUT DROP [130:14631]' >> /etc/iptables/rules.v4
echo ':FORWARD ACCEPT [0:0]' >> /etc/iptables/rules.v4
echo ':OUTPUT ACCEPT [0:0]' >> /etc/iptables/rules.v4
echo '#Allow Loopback  << the following two lines allow local loopback connection required for the reverse telnet to the device via Ser2Net.' >> /etc/iptables/rules.v4
echo '-A INPUT -i lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A OUTPUT -o lo -j ACCEPT' >> /etc/iptables/rules.v4
echo '# << The following entries only allow SSH on port 4044 to this host over the internet from only secured RWS site Brno and Maidenhead public IP’s.' >> /etc/iptables/rules.v4
echo '-A INPUT -s 192.168.0.0/16 -p tcp -m tcp --dport 4044 -j ACCEPT' >> /etc/iptables/rules.v4
echo '#-A INPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '#-A OUTPUT -j ACCEPT' >> /etc/iptables/rules.v4
echo '-A INPUT -j DROP' >> /etc/iptables/rules.v4
echo 'COMMIT' >> /etc/iptables/rules.v4
iptables-restore < /etc/iptables/rules.v4
echo '<<<Success>>>' 
echo '========================================================================================'
echo '===Rebooting system for settings to take affect..                                   ==='
echo '========================================================================================'
sleep 15
reboot
