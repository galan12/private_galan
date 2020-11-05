#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

cd "$(
    cd "$(dirname "$0")" || exit
    pwd
)" || exit
#====================================================
#	System Request:Debian 9+/Ubuntu 18.04+/Centos 7+
#	Author:	wulabing
#	Dscription: V2ray ws+tls onekey Management
#	Version: 1.0
#	email:admin@wulabing.com
#	Official document: www.v2ray.com
#====================================================

#fonts color
Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"


#notification information
# Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

# 版本
shell_version="1.1.5.7"
shell_mode="None"
github_branch="master"
version_cmp="/tmp/version_cmp.tmp"
v2ray_conf_dir="/etc/v2ray"
nginx_conf_dir="/etc/nginx/conf/conf.d"
v2ray_conf="${v2ray_conf_dir}/config.json"
nginx_conf="${nginx_conf_dir}/v2ray.conf"
nginx_dir="/etc/nginx"
web_dir="/home/wwwroot"
nginx_openssl_src="/usr/local/src"
v2ray_bin_dir_old="/usr/bin/v2ray"
v2ray_bin_dir="/usr/local/bin"
v2ray_info_file="$HOME/v2ray_info.inf"
v2ray_qr_config_file="/usr/local/vmess_qr.json"
nginx_systemd_file="/etc/systemd/system/nginx.service"
v2ray_systemd_file="/etc/systemd/system/v2ray.service"
v2ray_access_log="/var/log/v2ray/access.log"
v2ray_error_log="/var/log/v2ray/error.log"
amce_sh_file="/root/.acme.sh/acme.sh"
ssl_update_file="/usr/bin/ssl_update.sh"
nginx_version="1.18.0"
openssl_version="1.1.1g"
jemalloc_version="5.2.1"
old_config_status="off"
ssl_status="off"
# v2ray_plugin_version="$(wget -qO- "https://github.com/shadowsocks/v2ray-plugin/tags" | grep -E "/shadowsocks/v2ray-plugin/releases/tag/" | head -1 | sed -r 's/.*tag\/v(.+)\">.*/\1/')"

v2ray_dir=/galan/galan
domain=$1
http1=$2
httph2c=$3
api_port=$4
proxy_port=$5
new_uuid=b9f193c8-9849-0785-5bcd-a70d208ea1a5
	





#移动旧版本配置信息 对小于 1.1.0 版本适配
#[[ -f "/etc/v2ray/vmess_qr.json" ]] && mv /etc/v2ray/vmess_qr.json $v2ray_qr_config_file

#从VERSION中提取发行版系统的英文名称，为了在debian/ubuntu下添加相对应的Nginx apt源
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

#加载系统版本信息
source '/etc/os-release'


#检测是否第一次安装
check_first() {
if [[ -d /galan/galan ]]
then
	echo "检测到你的服务器已经安装，如需重新安装，请卸载后再执行安装"
	exit 2
fi
}
#检测传的参数是否正确
check_parameter() {
	if [[ ${http1} == "" ]] || [[ ${http1} -ge 65535 ]] || [[ ${http1} -eq 0 ]] 2>/dev/null
	then
		echo -e "${Yellow} 检测到你传入的第一个端口有误，已将端口修改为默认端口10011 ${Font}"
		http1=10011
	fi
	if [[ ${httph2c} == "" ]] || [[ ${httph2c} -ge 65535 ]] || [[ ${httph2c} -eq 0 ]] 2>/dev/null
	then
		echo -e "${Yellow} 检测到你传入的第二个端口有误，已将端口修改为默认端口10012 ${Font}"
		httph2c=10012
	fi
}



check_system() {
    if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
        INS="yum"
    elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
        INS="apt"
        $INS update
        ## 添加 Nginx apt源
    elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 16 ]]; then
        echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME} ${Font}"
        INS="apt"
        $INS update
    else
        echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
        exit 1
    fi

    $INS install -y dbus

    systemctl stop firewalld
    systemctl disable firewalld
    echo -e "${OK} ${GreenBG} firewalld 已关闭 ${Font}"

    systemctl stop ufw
    systemctl disable ufw
    echo -e "${OK} ${GreenBG} ufw 已关闭 ${Font}"
}

is_root() {
    if [ 0 == $UID ]; then
        echo -e "${OK} ${GreenBG} 当前用户是root用户，进入安装流程 ${Font}"
        sleep 3
    else
        echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
        exit 1
    fi
}

judge() {
    if [[ 0 -eq $? ]]; then
        echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} $1 失败${Font}"
        exit 1
    fi
}


chrony_install() {
    ${INS} -y install chrony
    judge "安装 chrony 时间同步服务 "

    timedatectl set-ntp true

    if [[ "${ID}" == "centos" ]]; then
        systemctl enable chronyd && systemctl restart chronyd
    else
        systemctl enable chrony && systemctl restart chrony
    fi

    judge "chronyd 启动 "

    timedatectl set-timezone Asia/Shanghai

    echo -e "${OK} ${GreenBG} 等待时间同步 ${Font}"
    sleep 10

    chronyc sourcestats -v
    chronyc tracking -v
    date
}

#安装必要的软件
dependency_install() {
    ${INS} install wget git lsof -y

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install crontabs
    else
        ${INS} -y install cron
    fi
    judge "安装 crontab"

    if [[ "${ID}" == "centos" ]]; then
        touch /var/spool/cron/root && chmod 600 /var/spool/cron/root
        systemctl start crond && systemctl enable crond
    else
        touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
        systemctl start cron && systemctl enable cron

    fi
    judge "crontab 自启动配置 "

    ${INS} -y install bc
    judge "安装 bc"

    ${INS} -y install unzip
    judge "安装 unzip"

    ${INS} -y install qrencode
    judge "安装 qrencode"

    ${INS} -y install curl
    judge "安装 curl"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y groupinstall "Development tools"
    else
        ${INS} -y install build-essential
    fi
    judge "编译工具包 安装"

    if [[ "${ID}" == "centos" ]]; then
        ${INS} -y install pcre pcre-devel zlib-devel epel-release qrencode
    else
        ${INS} -y install libpcre3 libpcre3-dev zlib1g-dev dbus qrencode
    fi

    #    ${INS} -y install rng-tools
    #    judge "rng-tools 安装"

    ${INS} -y install haveged
    #    judge "haveged 安装"

    #    sed -i -r '/^HRNGDEVICE/d;/#HRNGDEVICE=\/dev\/null/a HRNGDEVICE=/dev/urandom' /etc/default/rng-tools

    if [[ "${ID}" == "centos" ]]; then
        #       systemctl start rngd && systemctl enable rngd
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
    else
        #       systemctl start rng-tools && systemctl enable rng-tools
        #       judge "rng-tools 启动"
        systemctl start haveged && systemctl enable haveged
        #       judge "haveged 启动"
    fi
}


basic_optimization() {
    # 最大文件打开数
    sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
    echo '* soft nofile 65536' >>/etc/security/limits.conf
    echo '* hard nofile 65536' >>/etc/security/limits.conf

    # 关闭 Selinux
    if [[ "${ID}" == "centos" ]]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        setenforce 0
    fi

}

#------------------------------------------------------------------------------------------------




modify_UUID() {
	cd ${v2ray_dir}
    old_uuid=`cat config.json |grep id|awk '{print $2}'|awk -F \"  '{print $2}'`
	new_uuid=`./util uuid`
	sed -i "s#${old_uuid}#${new_uuid}#" config.json
}
modify_serverName() {
	cd ${v2ray_dir}
	serverName=`cat config.json |grep serverName |awk '{print $2}'|awk -F \" '{print $2}'`
	sed -i "s#${serverName}#${domain}#" config.json

}
modify_nginx_port() {
   cd ${nginx_conf_path_v2fly}
   old_http1=`cat v2fly.conf |grep listen|awk '{print $2}'|awk -F [:\;] 'NR==1{print $2}'`
   old_httph2c=`cat v2fly.conf |grep listen|awk '{print $2}'|awk -F [:\;] 'NR==2{print $2}'`
   old_server=`cat v2fly.conf |grep server_name|awk '{print $2}'`
   sed -i "s#${old_http1}#${http1}#" v2fly.conf
   sed -i "s#${old_httph2c}#${httph2c}#" v2fly.conf
   sed -i "s#${old_server}#${domain};#" v2fly.conf
   
#   cd ${v2ray_dir}
#   old_config_http1=`cat config.json|grep dest |awk 'NR==1{print $2}'`
#   old_config_httph2c=`cat config.json|grep dest |awk 'NR==2{print $2}'`
 #  sed -i "s#${old_config_http1}#${http1}#" config.json
 #  sed -i "s#${old_config_httph2c}#${httph2c}#" config.json
	
}
modify_ssl() {
    cd ${v2ray_dir}
	old_certificateFile=`cat config.json |grep certificateFile |awk '{print $2}'|awk -F \" '{print $2}'`
	old_keyFile=`cat config.json |grep keyFile |awk '{print $2}'|awk -F \" '{print $2}'`
	new_certificateFile=`ls /data/galan.crt`
	new_keyFile=`ls /data/galan.key`
	sed -i "s#${old_keyFile}#${new_keyFile}#" config.json
	sed -i "s#${old_certificateFile}#${new_certificateFile}#" config.json
}

modify_apiport() {
    cd ${v2ray_dir}
	old_apiport=`cat config.json |grep port |awk '{print $2}' |awk -F , 'NR==1{print $1}'`
	sed -i "s#${old_apiport}#${api_port}#" config.json
}

modify_proxy() {
    cd ${v2ray_dir}
	old_proxyport=`cat config.json |grep port |awk '{print $2}' |awk -F , 'NR==2{print $1}'`
	sed -i "s#${old_proxyport}#${proxy_port}#" config.json
}

v2ray_install() {
    if [[ -d /galan ]]; then
        rm -rf /galan
    fi
    mkdir -p /galan
    cd /galan || exit
    wget -N --no-check-certificate https://github.com/galan12/private_galan/raw/main/galan.tar.gz

    if [[ -f galan.tar.gz ]]; then
        tar -zxvf galan.tar.gz
		cd galan
    else
        echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
		rm -rf /galan
        exit 4
    fi
    # 清除临时文件
    rm -rf /galan/galan.tar.gz
}
#--------------------------------------------------------------------------------------------------------------------

nginx_exist_check() {
	rm -rf /etc/nginx/conf.d/v2fly.conf
	rm -rf /nginx_check
	rm -rf /nginx
	mkdir /nginx_check
	cd /nginx_check
	nginx -t > nginx.txt 2>&1
	status=`cat nginx.txt`
	
	if [[ ${status} =~ "bash" ]]
	then
		if [[ "${ID}" == "centos" ]]; then
			rpm -Uvh http://nginx.org/packages/centos/7/noarch/RPMS/nginx-release-centos-7-0.el7.ngx.noarch.rpm
			${INS} install -y nginx
		else
			apt-get update
			${INS} install -y nginx
		fi
		nginx_conf_path_v2fly=/etc/nginx/conf.d/
		cp -r /galan/galan/v2fly.conf /etc/nginx/conf.d/
		modify_nginx_port
		nginx -t
		if [[ $? -ne 0 ]]
		then
			echo "nginx配置错误"
			rm -rf /nginx_check
			exit 1
		else
			systemctl restart nginx
		fi
	elif [[ ${status} =~ "emerg" ]]
	then
		echo "服务器中已经安装的nginx配置报错，请排查后执行"
		rm -rf /nginx_check
		exit 2
	elif [[ ${status} =~ "successful" ]]
	then
		rm -rf /nginx/conf.d
		nginx_conf_path_v2fly=/nginx/conf.d
		nginx_conf_path=`cat nginx.txt |awk 'NR==1{print $5}'`
		http_conf=`cat ${nginx_conf_path} | grep http|grep {`
		a=`grep -A 1 "${http_conf}" ${nginx_conf_path}`
		if [[ ${a} =~ ${nginx_conf_path_v2fly} ]]
		then
			sed -i '/include\ \/nginx\/conf.d/d' /etc/nginx/nginx.conf
		fi
		sed -i "/${http_conf}/a\include /nginx/conf.d/*.conf;" /etc/nginx/nginx.conf
		mkdir -p /nginx/conf.d
		
		cp -r /galan/galan/v2fly.conf /nginx/conf.d
		modify_nginx_port
		nginx -t
		if [[ $? -ne 0 ]]
		then
			echo "nginx配置错误"
			exit 1
		else
			systemctl restart nginx
		fi
		
	fi
	rm -rf /nginx_check
}

ssl_install() {
    if [[ "${ID}" == "centos" ]]; then
        ${INS} install socat nc -y
    else
        ${INS} install socat netcat -y
    fi
    judge "安装 SSL 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    judge "安装 SSL 证书生成脚本"
}

domain_check() {
    #read -rp "请输入你的域名信息(eg:www.wulabing.com):" domain
    domain_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
    local_ip=$(curl https://api-ipv4.ip.sb/ip)
    echo -e "域名dns解析IP：${domain_ip}"
    echo -e "本机IP: ${local_ip}"
    sleep 2
    if [[ $(echo "${local_ip}" | tr '.' '+' | bc) -eq $(echo "${domain_ip}" | tr '.' '+' | bc) ]]; then
        echo -e "${OK} ${GreenBG} 域名dns解析IP 与 本机IP 匹配 ${Font}"
        sleep 2
    else
		if [[ -f /data/galan.key ]] && [[ -f /data/galan.crt ]]
		then
			ssl_status="on"
		else
			echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配，请确保域名添加了正确的 A 记录，否则将无法正常使用 galan ${Font}"
			echo -e "${Error} ${RedBG} 如果域名绑定的是你的ip,请确保你的出入网ip是否一致，如果不一致，请手动上传证书到/data/目录下将key文件 ${Font}"
			exit 2
		fi
		
        
    fi
}

port_exist_check() {
    if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
        echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
        lsof -i:"$1"
        echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
        sleep 5
        lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
        echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
        sleep 1
    fi
}

port_exist_check_443() {
	if [[ 0 -ne $(lsof -i:443 | grep -i -c "listen") ]] && [[ 0 -ne $(lsof -i:443 |grep -i "listen"|grep -i -c "nginx") ]]; then
		echo -e "${Error} ${RedBG} 检测到 443 端口被nginx占用，以下为 443 端口占用信息,请将nginx配置中的nginx关闭后执行 ${Font}"
		exit 1
	fi
}

	acme() {
		if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
			echo -e "${OK} ${GreenBG} SSL 证书测试签发成功，开始正式签发 ${Font}"
			rm -rf "$HOME/.acme.sh/${domain}_ecc"
			sleep 2
		else
			echo -e "${Error} ${RedBG} SSL 证书测试签发失败 ${Font}"
			rm -rf "$HOME/.acme.sh/${domain}_ecc"
			exit 1
		fi

		if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
			echo -e "${OK} ${GreenBG} SSL 证书生成成功 ${Font}"
			sleep 2
			mkdir /data
			if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/galan.crt --keypath /data/galan.key --ecc --force; then
				echo -e "${OK} ${GreenBG} 证书配置成功 ${Font}"
				sleep 2
			fi
		else
			echo -e "${Error} ${RedBG} SSL 证书生成失败 ${Font}"
			rm -rf "$HOME/.acme.sh/${domain}_ecc"
			exit 1
		fi
	}

v2ray_conf_update() {
	echo "修改config.json"
    cd /galan/galan
    modify_serverName
    modify_nginx_port
    modify_ssl
    modify_UUID
	modify_apiport
	modify_proxy
}





ssl_judge_and_install() {
	if [[ ${ssl_status} == "on" ]]
	then
		echo "手动上传证书成功"
	else
		if [[ -f "/data/galan.key" || -f "/data/galan.crt" ]]; then
			echo "证书文件已存在"
		elif [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" && -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
			echo "证书文件已存在"
			"$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/galan.crt --keypath /data/galan.key --ecc
			judge "证书应用"
		else
			ssl_install
			acme
		fi
	fi
    
}

up_galan() {
	cd /galan/galan
	/bin/bash start.sh
	echo -e "${OK} ${GreenBG} galan 安装成功,你可以手动输入信息到客户端，或者扫描二维码连接 ${Font}"
	echo -e "${OK} ${GreenBG} galan 配置信息 ${Font}"
	echo -e "${OK} ${GreenBG} 域名: ${domain} ${Font}"
	echo -e "${OK} ${GreenBG} proxy端口: ${proxy_port} ${Font}"
	echo -e "${OK} ${GreenBG} api端口: ${api_port} ${Font}"
	echo -e "${OK} ${GreenBG} uuid: ${new_uuid} ${Font}"
	#二维码
	
	#echo "${domain},443,${new_uuid}" | qrencode -o - -t UTF8
}








install_v2ray_ws_tls() {
	check_first
	#domain_check
	check_parameter
    is_root
    check_system
    chrony_install
    dependency_install
    basic_optimization
    domain_check
    #port_exist_check_443
    #old_config_exist_check
    #port_alterid_set
    v2ray_install
    port_exist_check 80
	port_exist_check 443
    port_exist_check "${http1}"
	port_exist_check "${httph2c}"
	ssl_judge_and_install
    nginx_exist_check
	
    v2ray_conf_update
	up_galan
    #web_camouflage
    
    #nginx_systemd
    #vmess_qr_config_tls_ws
    #basic_information
    #vmess_link_image_choice
    #tls_type
    #show_information
    #start_process_systemd
    #enable_process_systemd
    #acme_cron_update
}





#judge_mode
#list "$1"
install_v2ray_ws_tls

