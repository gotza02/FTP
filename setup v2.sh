#!/bin/bash
clear

# Color Definitions
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'

# System Information   
MYIP=$(wget -qO- ipinfo.io/ip)
REPO='https://package-9q1.pages.dev/'
idc='https://upload-dla.pages.dev/'
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minutes $((${1} % 60)) seconds"
}

# Status Functions
print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
    sleep 2
}

print_install() {
	echo -e "${Green} ┌──────────────────────────────────────────┐ ${FONT}"
    echo -e "${YELLOW} # Installing $1 "
	echo -e "${Green} └──────────────────────────────────────────┘ ${FONT}"
    sleep 2
    clear
}

print_success() {
	echo -e "${Green} ┌──────────────────────────────────────────┐ ${FONT}"
    echo -e "${YELLOW} # $1 installed successfully"
	echo -e "${Green} └──────────────────────────────────────────┘ ${FONT}"
    sleep 2
    clear
}

print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

# Check if root
is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user. Starting installation process."
    else
        print_error "Not root user. Please switch to root and rerun the script."
    fi
}

# Set System Environment
timedatectl set-timezone Asia/Jakarta
wget -O /etc/ssh/sshd_config ${REPO}config/sshd_config >/dev/null 2>&1
chmod 644 /etc/ssh/sshd_config
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# Update and Remove Unnecessary Packages
sudo apt autoremove git man-db apache2 ufw exim4 firewalld snapd* -y
clear
print_install "Installing necessary packages"
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
OS_ID=$(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g')
OS_NAME=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')
if [[ $OS_ID == "ubuntu" ]]; then
    echo "Setting up Dependencies for $OS_NAME"
    sudo apt update -y
    apt-get install --no-install-recommends software-properties-common
    add-apt-repository ppa:vbernat/haproxy-2.0 -y
    apt-get -y install haproxy=2.0.\*
elif [[ $OS_ID == "debian" ]]; then
    echo "Setting up Dependencies for $OS_NAME"
    curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-1.8 main >/etc/apt/sources.list.d/haproxy.list
    sudo apt-get update
    apt-get -y install haproxy=1.8.\*
else
    echo -e "Your OS ($OS_NAME) is not supported."
    exit 1
fi

sudo apt install software-properties-common at python squid dropbear fail2ban iptables iptables-persistent netfilter-persistent chrony cron resolvconf pwgen openssl netcat bash-completion ntpdate -y
sudo apt install xz-utils apt-transport-https dnsutils socat git tar lsof ruby zip unzip p7zip-full python3-pip libc6 gnupg gnupg2 gnupg1 -y
sudo apt install net-tools bc jq easy-rsa python3-certbot-nginx p7zip-full tuned -y
sudo apt install libopentracing-c-wrapper0 libopentracing1 linux-tools-common util-linux -y
apt-get install lolcat -y
gem install lolcat
dpkg --configure -a
apt --fix-broken install
apt-get install --fix-missing
print_ok "Necessary packages installed successfully"

# Create xray Directory
echo -e "Creating xray directory"
mkdir -p /etc/xray
mkdir -p /tmp/{menu,core}
clear

# Add Domain Function
add_domain() {
    echo -e "${red}┌──────────────────────────────────────────┐\033[0m${NC}"
    echo "          𝐌𝐚𝐤𝐡𝐥𝐮𝐤𝐓𝐮𝐧𝐧𝐞𝐥 "
    echo -e "${red}└──────────────────────────────────────────┘\033[0m${NC}"
    echo -e "${red}    ♦️${NC} ${green} CUSTOM SETUP DOMAIN VPS  ♦️${NC}"
    echo -e "${red}┌──────────────────────────────────────────┐\033[0m${NC}"
    echo "1. Use subdomain from script (makhlukvpn.my.id)"
    echo "2. Use your own subdomain"
    echo -e "${red}└──────────────────────────────────────────┘\033[0m${NC}"
    read -rp "Choose Your Domain Installation: " dom

    if [[ $dom -eq 1 ]]; then
        clear
        wget -O /tmp/dmn "${idc}/tools/DOMAIN" >/dev/null 2>&1
        bash /tmp/dmn && rm /tmp/dmn
        print_success "Domain Script"
    elif [[ $dom -eq 2 ]]; then
        read -rp "Enter Your Domain: " domen
        echo $domen > /etc/xray/domain
    else
        echo "Argument not found"
        add_domain
    fi
    clear
}
add_domain

# Install SSL Certificate
print_install "SSL Certificate"
domain=$(cat /etc/xray/domain)
STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
rm -rf /root/.acme.sh
mkdir /root/.acme.sh
systemctl stop $STOPWEBSERVER
systemctl stop nginx
sudo lsof -t -i tcp:80 -s tcp:listen | sudo xargs kill
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/haproxy.pem
chmod +x /etc/haproxy/haproxy.pem
chmod +x /etc/xray/xray.key
chmod +x /etc/xray/xray.crt
print_success "SSL Certificate installed"

mkdir -p /var/log/squid/cache/
chmod 777 /var/log/squid/cache/
echo "* - nofile 65535" >> /etc/security/limits.conf
mkdir -p /etc/sysconfig/
echo "ulimit -n 65535" >> /etc/sysconfig/squid

# Sync Time
chronyc sourcestats -v
chronyc tracking -v
# All Traffic IPTables Configuration
CMD=$(ip -o $CMD -4 route show to default | awk '{print $5}')
iptables -t nat -I PREROUTING -i $CMD -p udp --dport 53 -j REDIRECT --to-ports 5300
echo -e "Do you want to block torrent traffic? [yes/no]"
read block_torrent
# TCP Rules
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 109 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 143 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 10015 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 18020 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8080 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8880 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 3128 -j ACCEPT

# UDP Rules
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 53 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2200 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 7300 -j ACCEPT

# Block Torrent Traffic
if [ "$block_torrent" == "yes" ]; then
    # Block Torrent Traffic
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables -A FORWARD -m string --algo bm --string "/default.ida?" -j DROP
iptables -A FORWARD -m string --algo bm --string ".exe?/c+dir" -j DROP
iptables -A FORWARD -m string --algo bm --string ".exe?/c_tftp" -j DROP
iptables -A FORWARD -m string --algo kmp --string "peer_id" -j DROP
iptables -A FORWARD -m string --algo kmp --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo kmp --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo kmp --string "bittorrent-announce" -j DROP
iptables -A FORWARD -m string --algo kmp --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo kmp --string "find_node" -j DROP
iptables -A FORWARD -m string --algo kmp --string "info_hash" -j DROP
iptables -A FORWARD -m string --algo kmp --string "get_peers" -j DROP
iptables -A FORWARD -m string --algo kmp --string "announce" -j DROP
iptables -A FORWARD -m string --algo kmp --string "announce_peers" -j DROP
echo "Torrent traffic has been blocked."
else
    echo "Skipping blocking of torrent traffic."
fi
# NAT Configuration
iptables -t nat -I POSTROUTING -s 10.6.0.0/24 -o $CMD -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.7.0.0/24 -o $CMD -j MASQUERADE

# Save IPTables Rules
iptables-save >/etc/iptables/rules.v4 >/dev/null 2>&1
iptables-save >/etc/iptables.up.rules >/dev/null 2>&1
netfilter-persistent save >/dev/null 2>&1
netfilter-persistent reload >/dev/null 2>&1
systemctl enable iptables >/dev/null 2>&1 
systemctl start iptables >/dev/null 2>&1 
systemctl restart iptables >/dev/null 2>&1 

# Configure Dropbear
cat >/etc/default/dropbear <<-END
# Dropbear Configuration
NO_START=0
DROPBEAR_PORT=143
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER="/etc/issue.net"
DROPBEAR_RECEIVE_WINDOW=65536
END
chmod 644 /etc/default/dropbear

# Configure Squid
cat >/etc/squid/squid.conf <<-END
# Squid Proxy Configuration
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 1-9000
acl Safe_ports port 1-9000
acl CONNECT method CONNECT
acl SSH dst $MYIP
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 3128
coredump_dir /var/log/squid
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname $domain
END
# Download and Configure Websocket Python Script
wget -O /usr/sbin/ws.py "${REPO}core/python/stws.py" >/dev/null 2>&1
chmod +x /sbin/ws.py

# Configure HAProxy
cat >/etc/haproxy/haproxy.cfg<<-END
# HAProxy Configuration [MakhlukVPNTunnel Loadbalancer]
global       
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 1d
    tune.h2.initial-window-size 2147483647
    tune.ssl.default-dh-param 2048
    pidfile /run/haproxy.pid
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
    ca-base /etc/ssl/certs
    crt-base /etc/ssl/private

defaults
    log global
    mode tcp
    option dontlognull
    timeout connect 200ms
    timeout client 300s
    timeout server 300s
    
frontend multiport
    mode tcp
    bind-process 1 2
    bind *:443 tfo
    tcp-request inspect-delay 500ms
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend recir_http if HTTP 
    default_backend recir_https

frontend multiports
    mode tcp
    bind abns@haproxy-http accept-proxy tfo
    default_backend recir_https_www

frontend ssl
    mode tcp
    bind-process 1
    bind *:80 tfo
    bind *:8080 tfo
    bind *:8880 tfo
    bind abns@haproxy-https accept-proxy ssl crt /etc/haproxy/haproxy.pem alpn h2,http/1.1 tfo
    tcp-request inspect-delay 500ms
    tcp-request content capture req.ssl_sni len 100
    tcp-request content accept if { req.ssl_hello_type 1 }
    acl chk-02_up hdr(Connection) -i upgrade
    acl chk-02_ws hdr(Upgrade) -i websocket
    acl this_payload payload(0,7) -m bin 5353482d322e30
    use_backend MKVPN if chk-02_up chk-02_ws
    use_backend MKVPN if { path_reg -i ^\/(.*) }
    use_backend BOT_MKVPN if this_payload
    default_backend MKVPN

backend recir_https_www
    mode tcp
    server web-ssh 127.0.0.1:22 check

backend MKVPN
    mode http
    server xray-ws 127.0.0.1:10015 send-proxy check

backend BOT_MKVPN
    mode tcp
    server open-ssh 127.0.0.1:109 check
    
backend recir_http
    mode tcp
    server loopback-for-http abns@haproxy-http send-proxy-v2 check
   
backend recir_https
    mode tcp
    server loopback-for-https abns@haproxy-https send-proxy-v2 check
END

# Configure Websocket Service
cat >/etc/systemd/system/websocket.service <<-END
[Unit]
Description=SSH Over Websocket Python
Documentation=https://t.me/makhlukvpn_group
After=network.target nss-lookup.target

[Service]
Type=simple
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/sbin/ws.py
TimeoutStopSec=5
StandardOutput=journal
Restart=always
RestartSec=5 

[Install]
WantedBy=multi-user.target
END

# Download and Configure BadVPN
wget -O /usr/sbin/badvpn "${REPO}core/badvpn" >/dev/null 2>&1
chmod +x /usr/sbin/badvpn

# Configure BadVPN Service
cat >/etc/systemd/system/badvpn.service <<-END
[Unit]
Description=UDPGW 7300
Documentation=https://t.me/makhlukvpn_group
After=syslog.target network-online.target

[Service]
User=root
NoNewPrivileges=true
ExecStart=/usr/sbin/badvpn --listen-addr 127.0.0.1:7300 --max-clients 500
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
END

# Configure IPTables Service
cat >/etc/systemd/system/iptables.service <<-END
[Unit]
Description=netfilter persistent configuration
DefaultDependencies=no
Wants=network-pre.target systemd-modules-load.service local-fs.target
Before=network-pre.target shutdown.target
After=systemd-modules-load.service local-fs.target
Conflicts=shutdown.target
Documentation=man:netfilter-persistent(8)

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/netfilter-persistent start
ExecStop=/usr/sbin/netfilter-persistent stop

[Install]
WantedBy=multi-user.target
END

# Reload System Daemons
systemctl daemon-reload

# Enable and Start Services
systemctl enable --now netfilter-persistent 
systemctl start netfilter-persistent
systemctl enable --now badvpn
systemctl enable --now chronyd
systemctl enable --now dropbear
systemctl enable --now websocket
systemctl enable --now haproxy
systemctl enable --now iptables.service
systemctl enable --now squid
systemctl enable --now fail2ban

# Configure Nginx and Squid
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/ws.conf
sed -i "s/xxxx/${MYIP}/g" /etc/squid/squid.conf
sed -i "s/xxx/${domain}/g" /etc/squid/squid.conf

# Setup Custom Banner
cat >/etc/issue.net <<-END
<style>
  .banner {
    border: 2px solid blue;
    text-align: center;
    margin: 20px;
    padding: 10px;
  }
  .group {
    color: green;
    margin: 5px 0;
  }
  .qr-code {
    margin-top: 20px;
  }
</style>
</head>
<body>

<div class="banner">
  <div>[ GT Modify ]</div>
  <div>[ B Liv Thailand ]</div>
  <div class="group">Group [ True No Pro ] : <a href="https://line.me/ti/g2/85Eq587Kuuitlefk-qWfkQ4vy-mTJupon1owiQ?utm_source=invitation&utm_medium=link_copy&utm_campaign=default" target="_blank">Join our Line Group</a></div>
  <div class="qr-code">
    <img src="https://i.postimg.cc/m1QN7YC0/group-invite-QR-code1702003977698.jpg" alt="QR Code">
  </div>
</div>

</body>
END
# ...

echo "Choose the type of optimization you want to apply:"
echo "1. Network"
echo "2. Internet"
echo "3. RAM"
echo "4. CPU"
echo "5. All"
echo "6. None"
read -p "Enter your choice (1-6): " optimization_choice

case $optimization_choice in
    1)
        echo "Applying Network optimizations..."
echo "net.core.wmem_max=12582912" >> /etc/sysctl.conf
echo "net.core.rmem_max=12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem= 10240 87380 12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem= 10240 87380 12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 3240000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf
sysctl -p

        ;;
    2)
        echo "Applying Internet optimizations..."
        # Place your internet optimization commands here
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
sysctl -p
        ;;
    3)
        echo "Applying RAM optimizations..."
        # Place your RAM optimization commands here
        echo "vm.swappiness=10" >> /etc/sysctl.conf
echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
sysctl -p
        
        ;;
    4)
        echo "Applying CPU optimizations..."
        # Place your CPU optimization commands here
        echo "kernel.sched_migration_cost_ns = 5000000" >> /etc/sysctl.conf
sysctl -p
        ;;
    5)
        echo "Applying all optimizations..."
        # Place all your optimization commands here
        echo "net.core.wmem_max=12582912" >> /etc/sysctl.conf
echo "net.core.rmem_max=12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_rmem= 10240 87380 12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem= 10240 87380 12582912" >> /etc/sysctl.conf
echo "net.ipv4.tcp_window_scaling = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 3240000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
echo "vm.swappiness=10" >> /etc/sysctl.conf
echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
echo "kernel.sched_migration_cost_ns = 5000000" >> /etc/sysctl.conf

        ;;
    6)
        echo "No optimizations will be applied."
        ;;
    *)
        echo "Invalid choice. No optimizations will be applied."
        ;;
esac

echo "Optimization process completed."

# Rest of the script, including the restart command
# ...

echo "Installation is almost complete. Your server will reboot in 30 seconds."


echo "Subdomain used for this setup: $(cat /etc/xray/domain)"
rm -rf "setup v2.sh"
#!/bin/bash

# Ask the user if they want to reboot
read -p "Do you want to reboot the system? (y/n): " answer

# Check the user's answer
case $answer in
    [Yy]* ) sudo reboot;;
    [Nn]* ) echo "Reboot cancelled.";;
    * ) echo "Please answer yes or no.";;
esac
