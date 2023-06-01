#!/bin/bash
##############################################################################################
echo '===Installing Applications========='
sleep 5
sudo DEBIAN_FRONTEND=noninteractive apt-get install ser2net nano iptables-persistent telnet rsyslog cron iputils-ping moreutils net-tools -y
echo '###DONE!###'
##############################################################################################
echo '===Adding Cron job for auto maitenance==='
sleep 5
wget https://raw.githubusercontent.com/moislamm/UbuntuServer-Hardening-Script/main/deploy3-upgrade.sh && chmod 700 deploy3-upgrade.sh
echo "0 6 * * * /root/upgrade.sh >> /root/deploy3-upgrade.log 2>&1" > upgrade_crontab
crontab upgrade_crontab
rm upgrade_crontab
echo '###DONE!###'
##############################################################################################
echo '===Downloading Ser2NetFile========='
sleep 5
wget https://raw.githubusercontent.com/moislamm/UbuntuServer-Hardening-Script/main/ser2net.yaml && chmod 644 ser2net.yaml
mv ser2net.yaml /etc/ser2net.yaml
echo '###DONE!###'
##############################################################################################
echo '===Performing Update and Upgrade==='
sleep 5
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
echo '###DONE!###'
##############################################################################################
echo '===Creating SSH Banner============='
sudo touch /root/banner.txt
sudo chmod 600 /root/banner.txt
echo '#########################################' >> /root/banner.txt
echo '#          RESTRICTED SYSTEM            #' >> /root/banner.txt
echo '#                                       #' >> /root/banner.txt
echo '# ALL SYSTEM ACTIVITY IS MONITORED 24X7 #' >> /root/banner.txt
echo '#########################################' >> /root/banner.txt
echo '###DONE!###'
##############################################################################################
echo '===Secureing SSH rules============='
sleep 5
rm /etc/hosts.allow
sudo touch /etc/hosts.allow
sudo chmod 600 /etc/hosts.allow
rm /etc/hosts.deny
sudo touch /etc/hosts.deny
sudo chmod 600 /etc/hosts.deny
echo "sshd: 192.168.0.0/16" >> /etc/hosts.allow
echo "shd: ALL" >> /etc/hosts.deny
echo '###DONE!###'
##############################################################################################
echo '===Hardening SSH Application======='
sleep 5
rm /etc/ssh/sshd_config
touch /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
echo "Port 22" >> /etc/ssh/sshd_config
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
echo "Banner /root/banner.txt" >> /etc/ssh/sshd_config
echo '###DONE!###'
##############################################################################################
echo '===Hardening Kernel================'
sleep 5
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
echo '###DONE!###'
##############################################################################################
echo '===Disabling IPv6=================='
sleep 5
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX_DEFAULT=""/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/g' /etc/default/grub
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"/g' /etc/default/grub
sed -i '/GRUB_DEFAULT=0/,/ Uncomment to enable BadRAM/ s/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1"/g' /etc/default/grub
sudo update-grub
echo '###DONE!###'
##############################################################################################
echo '===Disabling Power=================='
sleep 5
echo "HandleSuspendKey=ignore" >> /etc/systemd/logind.conf
echo "HandleHibernateKey=ignore" >> /etc/systemd/logind.conf
echo "HandleLidSwitch=ignore" >> /etc/systemd/logind.conf
echo "HandleLidSwitchExternalPower=ignore" >> /etc/systemd/logind.conf
echo "HandleLidSwitchDocked=ignore" >> /etc/systemd/logind.conf
echo '###DONE!###'
##############################################################################################
echo '======================================================================='
echo '===Cleaning Files and Rebooting system for settings to take affect..==='
echo '======================================================================='
sleep 10
reboot
rm deploy3-script.sh
