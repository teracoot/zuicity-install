#!/usr/bin/env bash

# Zuicity one-click install / management script.

red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
ZUICITY_REPO="teracoot/zuicity"

latest_zuicity_version(){
    local version
    version=$(curl -fsSL "https://api.github.com/repos/${ZUICITY_REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z $version ]]; then
        version="v$(curl -fsSL "https://data.jsdelivr.com/v1/package/resolve/gh/${ZUICITY_REPO}" | grep '"version":' | sed -E 's/.*"([^"]+)".*/\1/')"
    fi
    echo "$version"
}

download_zuicity_zip(){
    local version=$1
    local output=$2
    local url="https://github.com/${ZUICITY_REPO}/releases/download/${version}/zuicity-linux-$(archAffix).zip"

    curl -fL -o "$output" "$url"
}

split_cert_chain(){
    local cert_file=$1
    local output_dir=$2

    awk -v dir="$output_dir" '
        /-----BEGIN CERTIFICATE-----/ { in_cert=1; n++; out=sprintf("%s/cert-%04d.pem", dir, n) }
        in_cert { print > out }
        /-----END CERTIFICATE-----/ { in_cert=0; close(out) }
        END { if (n == 0) exit 1 }
    ' "$cert_file"
}

cert_pin_sha256(){
    local tmp_dir cert_file cert_hash chain_hash next_hash pin

    tmp_dir=$(mktemp -d)
    cert_hash="$tmp_dir/cert.hash"
    chain_hash="$tmp_dir/chain.hash"
    next_hash="$tmp_dir/next.hash"

    if ! split_cert_chain "$cert_path" "$tmp_dir"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    for cert_file in "$tmp_dir"/cert-*.pem; do
        [[ -e $cert_file ]] || continue
        if ! openssl x509 -in "$cert_file" -outform DER 2>/dev/null | openssl dgst -sha256 -binary > "$cert_hash" 2>/dev/null; then
            rm -rf "$tmp_dir"
            return 1
        fi

        if [[ -s $chain_hash ]]; then
            cat "$chain_hash" "$cert_hash" | openssl dgst -sha256 -binary > "$next_hash" 2>/dev/null
            mv -f "$next_hash" "$chain_hash"
        else
            cp -f "$cert_hash" "$chain_hash"
        fi
    done

    pin=$(base64 "$chain_hash" 2>/dev/null | tr '+/' '-_' | tr -d '\n' | sed 's/=/%3D/g')
    rm -rf "$tmp_dir"
    echo "$pin"
}

cert_is_trusted(){
    [[ $cert_kind == "trusted" ]] && return 0

    local tmp_dir leaf_cert chain_cert cert_file status
    tmp_dir=$(mktemp -d)
    leaf_cert="$tmp_dir/cert-0001.pem"
    chain_cert="$tmp_dir/chain.pem"

    if ! split_cert_chain "$cert_path" "$tmp_dir" || [[ ! -f $leaf_cert ]]; then
        rm -rf "$tmp_dir"
        return 1
    fi

    for cert_file in "$tmp_dir"/cert-*.pem; do
        [[ $cert_file == "$leaf_cert" ]] && continue
        cat "$cert_file" >> "$chain_cert"
    done

    if [[ -s $chain_cert ]]; then
        openssl verify -verify_hostname "$hy_domain" -untrusted "$chain_cert" "$leaf_cert" >/dev/null 2>&1
    else
        openssl verify -verify_hostname "$hy_domain" "$leaf_cert" >/dev/null 2>&1
    fi
    status=$?
    rm -rf "$tmp_dir"
    return $status
}

make_share_link(){
    local host
    host=$(bracket_host "$ip")
    if cert_is_trusted; then
        shared_link="juicity://$uuid:$passwd@$host:$port?congestion_control=bbr&sni=$hy_domain"
        return
    fi

    local pin
    pin=$(cert_pin_sha256)
    if [[ -n $pin ]]; then
        shared_link="juicity://$uuid:$passwd@$host:$port?allow_insecure=1&congestion_control=bbr&pinned_certchain_sha256=$pin&sni=$hy_domain"
    else
        shared_link="juicity://$uuid:$passwd@$host:$port?allow_insecure=1&congestion_control=bbr&sni=$hy_domain"
    fi
}

bracket_host(){
    case "$1" in
        *:*) echo "[$1]" ;;
        *) echo "$1" ;;
    esac
}

# Non-public IPv4 per RFC1918/RFC6598 CGNAT(100.64/10)/RFC3927/loopback.
is_private_v4(){
    case "$1" in
        10.*) return 0 ;;
        192.168.*) return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
        169.254.*) return 0 ;;
        127.*) return 0 ;;
        100.6[4-9].*|100.7[0-9].*|100.8[0-9].*|100.9[0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
        0.*|255.255.255.255) return 0 ;;
    esac
    return 1
}

# Classify IPv6 by RFC4291/4193 prefix: 2000::/3 global, fc00::/7 ULA, fe80::/10 link-local.
classify_v6(){
    local addr="${1,,}" head dec
    [[ $addr == ::1 ]] && { echo loopback; return; }
    head="${addr%%:*}"
    [[ -z $head ]] && { echo other; return; }
    printf -v dec '%d' "0x$head" 2>/dev/null || { echo other; return; }
    if (( dec >= 0x2000 && dec <= 0x3fff )); then echo global
    elif (( dec >= 0xfe80 && dec <= 0xfebf )); then echo linklocal
    elif (( dec >= 0xfc00 && dec <= 0xfdff )); then echo ula
    else echo other
    fi
}

external_v4(){
    local svc out
    for svc in https://api.ipify.org https://ipv4.icanhazip.com https://v4.ident.me; do
        out=$(curl -4 -fsS --max-time 4 "$svc" 2>/dev/null | tr -d '[:space:]')
        if [[ $out =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && ! is_private_v4 "$out"; then
            echo "$out"; return 0
        fi
    done
    return 1
}

external_v6(){
    local svc out
    for svc in https://api6.ipify.org https://ipv6.icanhazip.com https://v6.ident.me; do
        out=$(curl -6 -fsS --max-time 4 "$svc" 2>/dev/null | tr -d '[:space:]')
        if [[ $out == *:* ]] && [[ $(classify_v6 "$out") == global ]]; then
            echo "$out"; return 0
        fi
    done
    return 1
}

collect_public_ips(){
    PUBLIC_IPS=()
    local addr have_v4="" have_v6=""
    declare -A _seen=()

    while read -r addr; do
        [[ -z $addr ]] && continue
        is_private_v4 "$addr" && continue
        [[ -n ${_seen[$addr]:-} ]] && continue
        _seen[$addr]=1; PUBLIC_IPS+=("$addr"); have_v4=1
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)

    while read -r addr; do
        [[ -z $addr ]] && continue
        [[ $(classify_v6 "$addr") == global ]] || continue
        [[ -n ${_seen[$addr]:-} ]] && continue
        _seen[$addr]=1; PUBLIC_IPS+=("$addr"); have_v6=1
    done < <(ip -6 -o addr show scope global -deprecated -tentative -temporary 2>/dev/null | awk '{print $4}' | cut -d/ -f1)

    if [[ -z $have_v4 ]]; then
        if addr=$(external_v4); then
            [[ -z ${_seen[$addr]:-} ]] && { _seen[$addr]=1; PUBLIC_IPS+=("$addr"); }
        fi
    fi
    if [[ -z $have_v6 ]]; then
        if addr=$(external_v6); then
            [[ -z ${_seen[$addr]:-} ]] && { _seen[$addr]=1; PUBLIC_IPS+=("$addr"); }
        fi
    fi
}

# Sets global $ip (bare) for link generation only; port binding stays wildcard.
select_public_ip(){
    collect_public_ips

    if [[ ${#PUBLIC_IPS[@]} -eq 0 ]]; then
        realip
        [[ -z $ip ]] && red "Could not determine any public IP address." && exit 1
        yellow "Using detected address for share links: $ip"
        return
    fi

    if [[ ${#PUBLIC_IPS[@]} -eq 1 ]]; then
        ip="${PUBLIC_IPS[0]}"
        yellow "Using public address for share links: $ip"
        return
    fi

    green "Multiple public addresses detected. Choose one for the share links:"
    echo ""
    local idx kind
    for idx in "${!PUBLIC_IPS[@]}"; do
        if [[ ${PUBLIC_IPS[idx]} == *:* ]]; then kind="IPv6"; else kind="IPv4"; fi
        echo -e " ${GREEN}$((idx+1)).${PLAIN} ${PUBLIC_IPS[idx]} ${YELLOW}($kind)${PLAIN}"
    done
    echo ""
    local choice
    while :; do
        read -rp "Enter option [1-${#PUBLIC_IPS[@]}]: " choice
        if [[ $choice =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#PUBLIC_IPS[@]} )); then
            ip="${PUBLIC_IPS[$((choice-1))]}"
            break
        fi
        yellow "Invalid choice; enter a number between 1 and ${#PUBLIC_IPS[@]}."
    done
    yellow "Selected address for share links: $ip"
}

make_tuic_share_link(){
    local host
    host=$(bracket_host "$ip")
    if cert_is_trusted; then
        tuic_link="tuic://$uuid:$passwd@$host:$port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$hy_domain"
    else
        tuic_link="tuic://$uuid:$passwd@$host:$port?allow_insecure=1&congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=$hy_domain"
    fi
}

make_client_security_config(){
    client_security_config=""
    if cert_is_trusted; then
        return
    fi

    local pin
    pin=$(cert_pin_sha256)
    client_security_config='    "allow_insecure": true,'
    if [[ -n $pin ]]; then
        client_security_config+=$'\n    "pinned_certchain_sha256": "'"$pin"$'",'
    fi
}

# Root check
[[ $EUID -ne 0 ]] && red "Note: please run this script as the root user" && exit 1

# OS detection
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
done

[[ -z $SYSTEM ]] && red "This script does not support the current OS." && exit 1

# Ensure curl + unzip exist
if [[ ! $(type -P curl) ]]; then
    ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
    ${PACKAGE_INSTALL[int]} curl >/dev/null 2>&1
fi
if [[ ! $(type -P unzip) ]]; then
    ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
    ${PACKAGE_INSTALL[int]} unzip >/dev/null 2>&1
fi
if [[ ! $(type -P openssl) ]]; then
    ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
    ${PACKAGE_INSTALL[int]} openssl >/dev/null 2>&1
fi

realip(){
    ip=$(curl -s4m8 ip.p3terx.com -k | sed -n 1p) || ip=$(curl -s6m8 ip.p3terx.com -k | sed -n 1p)
}

domain_points_to_server(){
    local requested_domain=$1
    local server_ip=$2
    local resolved_ips

    resolved_ips=$(getent ahostsv4 "$requested_domain" 2>/dev/null | awk '{print $1}' | sort -u)
    if [[ -z $resolved_ips ]]; then
        resolved_ips=$(getent ahosts "$requested_domain" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]+\.' | sort -u)
    fi

    [[ -n $resolved_ips ]] && grep -Fxq "$server_ip" <<< "$resolved_ips"
}

select_acme_issue_method(){
    acme_issue_args=(--standalone)

    local acme_webroot="/var/www/acme"
    local probe_token="zuicity-acme-probe-$(date +%s%N)"
    local challenge_dir="$acme_webroot/.well-known/acme-challenge"
    local challenge_file="$challenge_dir/$probe_token"
    local challenge_url="http://$domain/.well-known/acme-challenge/$probe_token"

    if systemctl is-active --quiet nginx && [[ -d $acme_webroot ]]; then
        mkdir -p "$challenge_dir"
        echo "$probe_token" > "$challenge_file"
        if [[ $(curl -sS --resolve "$domain:80:127.0.0.1" "$challenge_url" --max-time 8 2>/dev/null) == "$probe_token" ]]; then
            rm -f "$challenge_file"
            acme_issue_args=(-w "$acme_webroot")
            yellow "Using nginx webroot mode for ACME because port 80 is already served by nginx."
            return
        fi
        rm -f "$challenge_file"
    fi

    if ss -H -tln | awk '{print $4}' | grep -Eq '(^|[^0-9])80$'; then
        red "Port 80 is in use and no working ACME webroot route was found. Configure nginx to serve /.well-known/acme-challenge/ for $domain or free port 80, then retry."
        exit 1
    fi

    yellow "Using standalone mode for ACME because port 80 is free."
}

archAffix(){
    case "$(uname -m)" in
        x86_64 | amd64 ) echo 'x86_64' ;;
        * ) red "Unsupported CPU architecture for the current zuicity release!" && exit 1 ;;
    esac
}

inst_cert(){
    green "Select the certificate application method for Zuicity:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Self-signed certificate (bing.com) ${YELLOW}(default)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} acme.sh automatic certificate"
    echo -e " ${GREEN}3.${PLAIN} Use a certificate already on the server"
    echo ""
    read -rp "Enter option [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod -R 777 /var/log 2>/dev/null
        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            if [[ -x /root/.acme.sh/acme.sh ]]; then
                bash /root/.acme.sh/acme.sh --install-cert -d "$domain" --key-file /root/private.key --fullchain-file /root/cert.crt --reloadcmd "systemctl restart zuicity-server >/dev/null 2>&1 || true" --ecc >/dev/null 2>&1 || true
                sed -i '\|bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1\( # zuicity acme.sh auto-renew\)\?$|d' /etc/crontab >/dev/null 2>&1
                echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1 # zuicity acme.sh auto-renew" >> /etc/crontab
            fi
            green "A certificate for $domain was detected; it will be reused."
            hy_domain=$domain
            cert_kind="trusted"
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi

            read -rp "Enter the domain that resolves to this server: " domain
            [[ -z $domain ]] && red "No domain entered, certificate application aborted!" && exit 1
            green "Domain entered: $domain" && sleep 1
            if domain_points_to_server "$domain" "$ip"; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl >/dev/null 2>&1
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie >/dev/null 2>&1
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron >/dev/null 2>&1
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com >/dev/null 2>&1
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
                select_acme_issue_method
                if bash ~/.acme.sh/acme.sh --issue -d "$domain" "${acme_issue_args[@]}" -k ec-256 --insecure; then
                    bash ~/.acme.sh/acme.sh --install-cert -d "$domain" --key-file /root/private.key --fullchain-file /root/cert.crt --reloadcmd "systemctl restart zuicity-server >/dev/null 2>&1 || true" --ecc >/dev/null 2>&1
                    if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                        echo "$domain" > /root/ca.log
                        sed -i '\|bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1\( # zuicity acme.sh auto-renew\)\?$|d' /etc/crontab >/dev/null 2>&1
                        echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1 # zuicity acme.sh auto-renew" >> /etc/crontab
                        green "Certificate applied successfully; auto-renew configured." && sleep 1
                        hy_domain=$domain
                        cert_kind="trusted"
                    fi
                else
                    red "Certificate application failed." && exit 1
                fi
            else
                red "The domain does not resolve to this server's IP ($ip). Aborting." && exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -rp "Enter the public key (.crt) path: " cert_path
        yellow "Public key path: $cert_path"
        read -rp "Enter the private key (.key) path: " key_path
        yellow "Private key path: $key_path"
        read -rp "Enter the certificate domain: " domain
        yellow "Certificate domain: $domain"
        hy_domain=$domain
        cert_kind="existing"
    else
        green "A self-signed certificate (bing.com) will be generated for Zuicity." && sleep 1
        cert_path="/etc/zuicity/cert.crt"
        key_path="/etc/zuicity/private.key"
        mkdir -p /etc/zuicity
        openssl ecparam -genkey -name prime256v1 -out /etc/zuicity/private.key >/dev/null 2>&1
        openssl req -new -x509 -days 36500 -key /etc/zuicity/private.key -out /etc/zuicity/cert.crt -subj "/CN=www.bing.com" >/dev/null 2>&1
        chmod 777 /etc/zuicity/cert.crt
        chmod 777 /etc/zuicity/private.key
        hy_domain="www.bing.com"
        domain="www.bing.com"
        cert_kind="pinned"
    fi
}

inst_port(){
    read -rp "Set the Zuicity port [1-65535] (press Enter for a random port): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            yellow "Port $port is in use; choosing another."
            read -rp "Set the Zuicity port [1-65535] (press Enter for a random port): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done
    yellow "The Zuicity port is: $port"
}

inst_uuid(){
    yellow "A Zuicity UUID will be generated automatically; no input is needed."
    if [[ -n $(type -P zuicity-server) ]]; then
        uuid=$(zuicity-server generate-uuid 2>/dev/null | head -n1)
    fi
    [[ -z $uuid ]] && uuid=$(cat /proc/sys/kernel/random/uuid)
    yellow "The Zuicity UUID is: $uuid"
}

inst_pwd(){
    read -rp "Set the Zuicity password (press Enter for a random one): " passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "The Zuicity password is: $passwd"
}

instzuicity(){
    if [[ -f /etc/systemd/system/zuicity-server.service ]]; then
        red "Zuicity is already installed. Use the management menu instead." && exit 1
    fi

    inst_cert
    inst_port
    inst_uuid
    inst_pwd

    last_version=$(latest_zuicity_version)
    [[ -z $last_version || $last_version == "v" ]] && red "Failed to detect the zuicity version." && exit 1
    green "Detected zuicity version: $last_version"

    tmp_dir=$(mktemp -d)
    if ! download_zuicity_zip "$last_version" "$tmp_dir/zuicity.zip"; then
        red "Failed to download the zuicity release." && rm -rf "$tmp_dir" && exit 1
    fi
    ( cd "$tmp_dir" && unzip -o zuicity.zip >/dev/null 2>&1 )
    cp -f "$tmp_dir/zuicity-server" /usr/bin/zuicity-server
    cp -f "$tmp_dir/zuicity-client" /usr/bin/zuicity-client 2>/dev/null
    chmod +x /usr/bin/zuicity-server /usr/bin/zuicity-client 2>/dev/null
    cp -f "$tmp_dir/zuicity-server.service" /etc/systemd/system/zuicity-server.service
    rm -rf "$tmp_dir"

    mkdir -p /etc/zuicity
    cat > /etc/zuicity/server.json <<EOF
{
    "listen": "[::]:$port",
    "users": {
        "$uuid": "$passwd"
    },
    "certificate": "$cert_path",
    "private_key": "$key_path",
    "congestion_control": "bbr",
    "log_level": "info"
}
EOF

    systemctl daemon-reload
    systemctl enable zuicity-server >/dev/null 2>&1
    systemctl start zuicity-server

    if [[ -n $(systemctl status zuicity-server 2>/dev/null | grep -w active) ]]; then
        green "Zuicity service started successfully."
    else
        red "Zuicity failed to start. Check: journalctl -u zuicity-server" && exit 1
    fi

    select_public_ip
    mkdir -p /root/zuicity

    make_share_link
    make_tuic_share_link
    make_client_security_config
    echo "$shared_link" > /root/zuicity/url.txt
    echo "$tuic_link" > /root/zuicity/url-tuic.txt

    cat > /root/zuicity/client.json <<EOF
{
    "listen": "127.0.0.1:1080",
    "server": "$(bracket_host "$ip"):$port",
    "uuid": "$uuid",
    "password": "$passwd",
    "sni": "$hy_domain",
$client_security_config
    "congestion_control": "bbr",
    "log_level": "info"
}
EOF

    showconf
}

unstzuicity(){
    systemctl stop zuicity-server >/dev/null 2>&1
    systemctl disable zuicity-server >/dev/null 2>&1
    rm -f /etc/systemd/system/zuicity-server.service
    systemctl daemon-reload
    rm -f /usr/bin/zuicity-server /usr/bin/zuicity-client
    rm -rf /etc/zuicity /root/zuicity
    green "Zuicity has been completely uninstalled."
}

startzuicity(){
    systemctl start zuicity-server
    systemctl enable zuicity-server >/dev/null 2>&1
    green "Zuicity started."
}

stopzuicity(){
    systemctl stop zuicity-server
    green "Zuicity stopped."
}

zuicityswitch(){
    yellow "Choose an action:"
    echo -e " ${GREEN}1.${PLAIN} Start Zuicity"
    echo -e " ${GREEN}2.${PLAIN} Stop Zuicity"
    echo -e " ${GREEN}3.${PLAIN} Restart Zuicity"
    echo ""
    read -rp "Enter option [1-3]: " switchInput
    case $switchInput in
        1 ) startzuicity ;;
        2 ) stopzuicity ;;
        3 ) stopzuicity && startzuicity ;;
        * ) exit 1 ;;
    esac
}

changeconf(){
    green "Zuicity configuration options:"
    echo -e " ${GREEN}1.${PLAIN} Change the port"
    echo -e " ${GREEN}2.${PLAIN} Change the UUID"
    echo -e " ${GREEN}3.${PLAIN} Change the password"
    echo ""
    read -rp "Enter option [1-3]: " confAnswer
    case $confAnswer in
        1 )
            oldport=$(grep '"listen"' /etc/zuicity/server.json | sed -E 's/.*:([0-9]+).*/\1/')
            inst_port
            sed -i -E "s/\"listen\": \"(0\.0\.0\.0|\[::\]):$oldport\"/\"listen\": \"[::]:$port\"/" /etc/zuicity/server.json
            stopzuicity && startzuicity
            ;;
        2 )
            olduuid=$(grep -E '"[0-9a-fA-F-]{36}"' /etc/zuicity/server.json | head -n1 | sed -E 's/.*"([0-9a-fA-F-]{36})".*/\1/')
            inst_uuid
            sed -i "s/$olduuid/$uuid/" /etc/zuicity/server.json
            stopzuicity && startzuicity
            ;;
        3 )
            inst_pwd
            uuid=$(grep -E '"[0-9a-fA-F-]{36}"' /etc/zuicity/server.json | head -n1 | sed -E 's/.*"([0-9a-fA-F-]{36})".*/\1/')
            sed -i -E "s/(\"$uuid\": \")[^\"]*(\")/\1$passwd\2/" /etc/zuicity/server.json
            stopzuicity && startzuicity
            ;;
        * ) exit 1 ;;
    esac
    green "Configuration updated. Refresh the share link from the menu (option 5)."
}

showconf(){
    yellow "Zuicity client config (/root/zuicity/client.json):"
    cat /root/zuicity/client.json 2>/dev/null
    echo ""
    yellow "Zuicity share link (/root/zuicity/url.txt):"
    red "$(cat /root/zuicity/url.txt 2>/dev/null)"
    echo ""
    yellow "TUIC share link (/root/zuicity/url-tuic.txt):"
    red "$(cat /root/zuicity/url-tuic.txt 2>/dev/null)"
    echo ""
}

updatezuicity(){
    if [[ ! -f /etc/systemd/system/zuicity-server.service ]]; then
        red "Zuicity is not installed." && exit 1
    fi
    last_version=$(latest_zuicity_version)
    [[ -z $last_version || $last_version == "v" ]] && red "Failed to detect the zuicity version." && exit 1
    green "Updating to zuicity $last_version ..."

    tmp_dir=$(mktemp -d)
    if ! download_zuicity_zip "$last_version" "$tmp_dir/zuicity.zip"; then
        red "Download failed." && rm -rf "$tmp_dir" && exit 1
    fi
    ( cd "$tmp_dir" && unzip -o zuicity.zip >/dev/null 2>&1 )
    cp -f "$tmp_dir/zuicity-server" /usr/bin/zuicity-server
    cp -f "$tmp_dir/zuicity-client" /usr/bin/zuicity-client 2>/dev/null
    cp -f "$tmp_dir/zuicity-server.service" /etc/systemd/system/zuicity-server.service
    chmod +x /usr/bin/zuicity-server /usr/bin/zuicity-client 2>/dev/null
    rm -rf "$tmp_dir"

    systemctl daemon-reload
    systemctl restart zuicity-server
    green "Zuicity updated to $last_version and restarted."
}

menu(){
    clear
    echo "#############################################################"
    echo -e "#                  ${RED}Zuicity one-click script${PLAIN}                  #"
    echo -e "#  ${GREEN}Project:${PLAIN} zuicity (QUIC-based proxy)                      #"
    echo "#############################################################"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Install Zuicity"
    echo -e " ${GREEN}2.${PLAIN} ${RED}Uninstall Zuicity${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} Start / Stop / Restart Zuicity"
    echo -e " ${GREEN}4.${PLAIN} Change Zuicity configuration"
    echo -e " ${GREEN}5.${PLAIN} Show Zuicity config and share link"
    echo " -------------"
    echo -e " ${GREEN}6.${PLAIN} Update Zuicity"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} Exit"
    echo ""
    read -rp "Enter option [0-6]: " menuInput
    case $menuInput in
        1 ) instzuicity ;;
        2 ) unstzuicity ;;
        3 ) zuicityswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) updatezuicity ;;
        * ) exit 0 ;;
    esac
}

menu
