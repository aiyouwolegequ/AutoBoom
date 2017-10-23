#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

IP=`wget -qO- -t1 -T2 ipv4.icanhazip.com`

rootness(){

	if [ $(id -u) != "0" ]; then
		echo "错误:该脚本需要root权限运行!请切换至root权限！"
		exit 1
	fi
}

get_char(){

	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
}

tunavailable(){

	if [[ ! -e /dev/net/tun ]]; then
		echo "错误:无法安装L2TP" 1>&2
		any_key_to_continue
		mainmenu
	fi
}

disable_selinux(){

	selinux=`getenforce`

	if [[ "$selinux" = "Enforcing" ]] ; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
		setenforce 0
		echo "SElinux已禁用..."
		echo ""
		echo "#######################################################################"
	fi
}

get_opsy(){

	[ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
}

get_os_info(){

	local cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
	local cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	local freq=$( awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//' )
	local tram=$( free -m | awk '/Mem/ {print $2}' )
	local swap=$( free -m | awk '/Swap/ {print $2}' )
	local up=$( awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60;d=$1%60} {printf("%ddays, %d:%d:%d\n",a,b,c,d)}' /proc/uptime )
	local load=$( w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//' )
	local opsy=$( get_opsy )
	local arch=$( uname -m )
	local lbit=$( getconf LONG_BIT )
	local host=$( hostname )
	local kern=$( uname -r )
	echo ""
	echo "################ 系统信息 ################"
	echo ""
	echo "CPU 型号	: ${cname}"
	echo "CPU 核心数	: ${cores}"
	echo "CPU 频率	: ${freq} MHz"
	echo "内存大小	: ${tram} MB"
	echo "缓存大小	: ${swap} MB"
	echo "开机运行时间	: ${up}"
	echo "平均负载	: ${load}"
	echo "系统		: ${opsy}"
	echo "位数		: ${arch} (${lbit} Bit)"
	echo "内核		: ${kern}"
	echo "主机名		: ${host}"
	echo "IP地址		: ${IP}"
	echo ""
	echo "########################################"
	echo ""
	any_key_to_continue
}

command_exists(){

	command -v "$@" >/dev/null 2>&1
}

rebootcheck(){

	read -p "刚刚更新了系统内核，是否重启系统 ? (y/n) [默认=n]:" xy1
	echo "#######################################################################"
	case $xy1 in
		y|Y)
		init 6
		;;
		n|N)
		submenu1
		;;
		*)
		submenu1
		;;
	esac
}

set_sysctl(){

	for each in `ls /proc/sys/net/ipv4/conf/`; do
		echo "net.ipv4.conf.${each}.accept_source_route=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.accept_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.send_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.rp_filter=0" >> /etc/sysctl.conf
	done

	echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
	echo "net.core.rmem_max = 67108864" >> /etc/sysctl.conf
	echo "net.core.wmem_max = 67108864" >> /etc/sysctl.conf
	echo "net.core.somaxconn = 4096" >> /etc/sysctl.conf
	echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	echo "net.ipv4.ip_local_port_range = 10000 65000" >> /etc/sysctl.conf
	echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
	echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_max_syn_backlog = 20480" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_max_tw_buckets = 400000" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_no_metrics_save = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_rmem = 4096 87380 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_wmem = 4096 65536 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_mem = 25600 51200 102400" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syn_retries = 2" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	echo "vm.min_free_kbytes = 65536" >> /etc/sysctl.conf
	echo "fs.file-max = 51200" >> /etc/sysctl.conf
}

any_key_to_continue(){

	echo -e "请手动按任意键继续执行脚本或按\e[0;31m Ctrl + C\e[0m 退出"
	local saved=
	saved="$(stty -g)"
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2>/dev/null
	stty -raw
	stty echo
	stty $saved
}

auto_continue(){

	seconds_left=5 
	while [ $seconds_left -gt 0 ];
	do
		echo -e -n "脚本将在\e[0;31m${seconds_left}\e[0m秒后继续执行或按\e[0;31m Ctrl + C\e[0m 手动退出 ...\r"
		sleep 1
		seconds_left=$(($seconds_left - 1))
	done	
}

randusername(){

	str=""
	cat /dev/urandom | head -n 10 | md5sum | awk -F ' ' '{print $1}' | cut -c-7
	echo ${str}
}

randpsk(){

	str=""
	cat /dev/urandom | head -n 10 | md5sum | awk -F ' ' '{print $1}' | cut -c-10
	echo ${str}
}

randpasswd(){

	str=""
	cat /dev/urandom | head -n 10 | md5sum | awk -F ' ' '{print $1}' | cut -c-12
	echo ${str}
}

pre_install(){

	clear
	echo "#######################################################################"
	echo ""
	echo "预安装相关软件！"
	echo ""
	echo "#######################################################################"
	cat >/etc/profile<<-EOF
	export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	EOF
	source /etc/profile
	rm -f /var/run/yum.pid
	yum install epel-release elrepo-release yum-fastestmirror yum-utils -y
	yum groupinstall "Development Tools" -y
	rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
	rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
	rpm -Uvh http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
	cd /etc/yum.repos.d/
	wget https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/repo/epel-7/librehat-shadowsocks-epel-7.repo
	cd
	yum install gcc gettext swig autoconf libtool python-setuptools automake pcre-devel asciidoc xmlto c-ares-devel libev-devel libsodium-devel ibevent mbedtls-devel m2crypto libtool-ltdl-devel libevent-devel wget gawk tar  policycoreutils-python gcc+ glibc-static libstdc++-static wget iproute net-tools bind-utils finger vim git make selinux-policy-devel -y
	ldconfig
	easy_install pip
	clear
	echo "#######################################################################"
	echo ""
	echo "预安装完成！"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

updatesystem(){

	clear
	echo "#######################################################################"
	echo ""
	echo "正在升级系统"
	echo ""
	echo "#######################################################################"
	cd
	yum check-update
	yum info updates
	yum upgrade -y
	yum update -y
	yum repolist
	yum autoremove
	yum makecache
	yum-complete-transaction --cleanup-only
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm -Va --nofiles --nodigest
	yum clean all
	rm -rf /var/cache/yum
	rpm --rebuilddb
	yum update -y
	cat /etc/redhat-release
	echo "#######################################################################"
	echo ""
	echo "升级完毕！"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

updatekernel(){

	clear
	echo "#######################################################################"
	echo ""
	echo "正在升级内核,请在全部脚本完成后重启系统"
	echo ""
	echo "#######################################################################"
	yum --enablerepo=elrepo-kernel install kernel-ml -y
	egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
	grub2-set-default 0
	modprobe tcp_bbr
	modprobe tcp_htcp
	modprobe tcp_hybla
	echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
	sysctl net.ipv4.tcp_available_congestion_control
	lsmod | grep bbr
	sysctl -p
	echo "#######################################################################"
	echo ""
	echo "升级完毕！"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

changerootpasswd(){

	newrootpasswd=`randpasswd`
	clear
	echo "#######################################################################"
	echo ""
	echo "正在更换root密码!"
	echo ""
	echo "#######################################################################"
	echo "${newrootpasswd}" | passwd --stdin root
	echo "#######################################################################"
	echo ""
	echo -e "新root密码为	:\033[41;30m${newrootpasswd}\033[0m" 
	echo "请妥善保存root密码！"
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

add_newuser(){

	newusername=`randusername`
	newuserpasswd=`randpasswd`
	clear
	echo "#######################################################################"
	echo ""
	echo "新建一个非root权限的系统用户!"
	echo ""
	echo "#######################################################################"
	useradd -m ${newusername}
	echo "${newuserpasswd}" | passwd --stdin ${newusername}
	echo "#######################################################################"
	echo ""
	echo "请保存好用户名和密码！"
	echo -e "用户名	:\033[41;30m${newusername}\033[0m" 
	echo -e "密码	:\033[41;30m${newuserpasswd}\033[0m" 
	echo ""
	echo "#######################################################################"
	echo ""
	echo "#######################################################################"
	echo ""

	read -p "是否需要设置ssh ? (y/n) [默认=n]:" yn
	case "$yn" in
		y|Y)
			clear
			echo "#######################################################################"
			echo ""
			echo "更换ssh端口为10010，禁用root登陆ssh，禁用密码认证，设置免密钥登陆"
			echo ""
			echo "#######################################################################"
			cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/
			sed -i 's/22/10010/g' /etc/firewalld/services/ssh.xml
			firewall-cmd --zone=public --add-port=10010/tcp --permanent
			firewall-cmd --reload 
			semanage port -a -t ssh_port_t -p tcp 10010
			semanage port -l |grep ssh
			cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
			echo "Port 10010" >>/etc/ssh/sshd_config
			echo "PermitRootLogin no" >> /etc/ssh/sshd_config
			echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
			sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
			su - ${newusername} -c "ssh-keygen -t rsa -P '' -f /home/${newusername}/.ssh/id_rsa"
			su - ${newusername} -c "touch /home/${newusername}/.ssh/authorized_keys"
			su - ${newusername} -c "chmod 700 /home/${newusername}/.ssh"
			su - ${newusername} -c "chmod 600 /home/${newusername}/.ssh/authorized_keys"

			while :
			do
				echo "#######################################################################"
				echo ""
				read -p "请输入管理该服务器的电脑的公钥（可以使用cat .ssh/id_rsa.pub查看）:" pub
					echo ""
					echo "#######################################################################"
					if [ -z "${pub}" ]; then
						echo "公钥不能为空"
					else
				 		su - ${newusername} -c "echo ${pub} >> /home/${newusername}/.ssh/authorized_keys"
				 		break
				 	fi
			done

			systemctl restart sshd.service
			echo "请使用该命令测试ssh是否正常: ssh -p 10010 ${newusername}@${IP}"
			echo "#######################################################################"

			read -p "请确认ssh是否正常? (y/n) [默认=y]:" yy
				echo "#######################################################################"
				case "$yy" in
					y|Y)
						echo ""
						any_key_to_continue
						;;
					n|N)
						clear
						echo "#######################################################################"
						echo ""
						echo "恢复ssh端口为22 ,允许root登陆，允许使用密码验证"
						echo ""
						echo "#######################################################################"
						rm -rf /etc/ssh/sshd_config
						mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
						sed -i 's/10010/22/g' /etc/firewalld/services/ssh.xml
								firewall-cmd --zone=public --remove-port=10010/tcp --permanent
								firewall-cmd --reload
						semanage port -d -t ssh_port_t -p tcp 10010
						systemctl restart sshd
						echo "请使用该命令测试ssh是否正常: ssh root@${IP}"
						echo "请在脚本完成后手动设置ssh密钥登陆"
						echo "#######################################################################"
						echo ""
						any_key_to_continue
						;;
					*)
						echo ""
						any_key_to_continue
						;;
				esac
			;;
		n|N)
			install_ckrootkit_rkhunter
			;;
		*)
			install_ckrootkit_rkhunter
			;;
	esac
}

install_ckrootkit_rkhunter(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装ckrootkit和rkhunter"
	echo ""
	echo "#######################################################################"
	echo ""
	yum install rkhunter -y
	wget --tries=3 ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz

	if
		[ -a chkrootkit.tar.gz ];
	then	
		tar zxf chkrootkit.tar.gz
		cd chkrootkit-*
		make clean
		ldconfig
		make sense
		cd ..
		mv -f chkrootkit-* chkrootkit
		rm -rf /usr/local/chkrootkit
		mv -f chkrootkit /usr/local/
		chown -R root:root /usr/local/chkrootkit
		chmod -R 700 /usr/local/chkrootkit
		ln -s -f /usr/local/chkrootkit/chkrootkit /usr/local/bin/chkrootkit
	fi

	cat >> ~/.zshrc<<-EOF
	export PATH="/usr/local/bin/:$PATH"
	EOF

	rkhunter --update
	rkhunter --propupd
	clear
	echo "#######################################################################"
	echo ""
	echo "正在检测系统，请耐心等待!日志保存在chkrootkit.log和rkhunter.log"
	echo ""
	echo "#######################################################################"
	echo ""
	rkhunter --check --sk |grep Warning
	chkrootkit >> chkrootkit.log
	cat chkrootkit.log| grep INFECTED 
	mv /var/log/rkhunter/rkhunter.log ./
	rm -rf chkrootkit*
	echo "#######################################################################"
	echo ""
	echo "ckrootkit和rkhunter安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_fail2ban(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装fail2ban"
	echo ""
	echo "#######################################################################"
	echo ""
	yum install fail2ban fail2ban-firewalld fail2ban-systemd -y
	cp -pf /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

	cat > /etc/fail2ban/jail.local<<-EOF
	[DEFAULT]
	bantime = 86400
	findtime = 600
	maxretry = 3
	EOF

	cat > /etc/fail2ban/jail.d/sshd.local<<-EOF
	[sshd]
	enabled = true
	port = 10010
	#action = firewallcmd-ipset
	logpath = %(sshd_log)s
	maxretry = 3
	bantime = 86400
	EOF

	systemctl enable firewalld
	systemctl start firewalld
	systemctl enable fail2ban
	systemctl start fail2ban
	fail2ban-client status
	fail2ban-client status sshd
	echo "#######################################################################"
	echo ""
	echo -e "fail2ban安装完毕，使用\033[41;30mfail2ban-client status sshd\033[0m可以查看屏蔽列表."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_lynis(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装lynis"
	echo ""
	echo "#######################################################################"
	echo ""
	git clone https://github.com/CISOfy/lynis
	mv lynis /usr/local/
	ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
	lynis update info
	echo "#######################################################################"
	echo ""
	echo "正在检测系统，请耐心等待!日志保存在lynis.log"
	echo ""
	echo "#######################################################################"
	lynis audit system | tee lynis.log
	echo "#######################################################################"
	echo ""
	echo "lynis安装完成,日志保存在lynis.log."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_zsh(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装zsh"
	echo ""
	echo "#######################################################################"
	echo ""
	cd
	yum install zsh -y
	umask g-w,o-w

	if [ ! -n "$ZSH" ]; then
		ZSH=~/.oh-my-zsh
	fi

	env git clone --depth=1 https://github.com/robbyrussell/oh-my-zsh.git $ZSH
	cp $ZSH/templates/zshrc.zsh-template ~/.zshrc
	sed "/^export ZSH=/ c\\
	export ZSH=$ZSH
	" ~/.zshrc > ~/.zshrc-omztemp
	mv -f ~/.zshrc-omztemp ~/.zshrc

	cd /root/.oh-my-zsh/themes
	git clone https://github.com/dracula/zsh.git
	mv zsh/dracula.zsh-theme .
	rm -rf zsh
	sed -i 's/robbyrussell/dracula/g' ~/.zshrc
	sed -i 's/plugins=(git)/plugins=(sudo zsh-syntax-highlighting git autojump web-search zsh_reload colored-man-pages zsh-autosuggestions zsh-history-substring-search)/g' ~/.zshrc
	cd /root/.oh-my-zsh/plugins
	git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
	git clone https://github.com/zsh-users/zsh-autosuggestions.git
	git clone https://github.com/zsh-users/zsh-history-substring-search.git

	cat >> /root/.zshrc<<-EOF
	export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	alias vizsh="vim ~/.zshrc"
	alias sourcezsh="source ~/.zshrc"
	EOF

	source /root/.zshrc
	TEST_CURRENT_SHELL=$(expr "$SHELL" : '.*/\(.*\)')

	if [ "$TEST_CURRENT_SHELL" != "zsh" ]; then
  		if hash chsh >/dev/null 2>&1; then
  			clear
  			cd
 		 	chsh -s /bin/zsh root
 		 	echo "#######################################################################"
			echo ""
 		 	echo -e "请手动输入\033[41;30mexit\033[0m继续执行脚本...!"
 		 	echo "千万不要按Ctrl + C退出脚本!!!"
			echo ""
			echo "#######################################################################"
	else
  			echo "请手动修改默认shell为zsh!"
 		fi
	fi
  	env zsh
	echo "#######################################################################"
	echo ""
	echo "Zsh安装完毕，脚本完成后使用env zsh手动切换shell为zsh."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_shadowsocks(){

	clear
	sspasswd=`randpasswd`
	echo "#######################################################################"
	echo ""
	echo "开始安装Shadowsocks"
	echo ""
	echo "#######################################################################"
	echo ""
	yum install shadowsocks-libev -y
	pip install greenlet
	pip install gevent
	firewall-cmd --zone=public --add-port=999/tcp --permanent
	firewall-cmd --zone=public --add-port=999/udp --permanent
	firewall-cmd --reload
	firewall-cmd --list-ports
	systemctl restart firewalld.service
	systemctl -a | grep firewalld

	cat > /etc/shadowsocks-libev/config.json<<-EOF
	{
	    "server":"${IP}",
	    "server_port":999,
	    "local_port":1080,
	    "password":"${sspasswd}",
	    "timeout":60,
	    "method":"chacha20-ietf-poly1305"
	 }
	EOF

	cat > /etc/sysconfig/shadowsocks-libev<<-EOF
	START=yes
	CONFFILE="/etc/shadowsocks-libev/config.json"
	DAEMON_ARGS="-u --fast-open"
	USER=root
	GROUP=root
	MAXFD=32768
	EOF

	cat > /usr/lib/systemd/system/shadowsocks-libev.service<<-EOF
	[Unit]
	Description=Shadowsocks-libev Default Server Service
	Documentation=man:shadowsocks-libev(8)
	After=network.target

	[Service]
	Type=simple
	EnvironmentFile=/etc/sysconfig/shadowsocks-libev
	User=root
	Group=root
	LimitNOFILE=32768
	ExecStart=/usr/bin/ss-server -a \$USER -c \$CONFFILE \$DAEMON_ARGS

	[Install]
	WantedBy=multi-user.target
	EOF

	systemctl daemon-reload
	systemctl start shadowsocks-libev.service
	systemctl enable shadowsocks-libev.service
	systemctl -a | grep shadowsocks-libev
	echo "#######################################################################"
	echo ""
	echo "Shadowsocks安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	echo "Shadowsocks的相关配置:"
	echo -e "服务器IP	:	\033[41;30m${IP}\033[0m"
	echo -e "端口		:	\033[41;30m999\033[0m"
	echo -e "密码		:	\033[41;30m${sspasswd}\033[0m"
	echo -e "加密方式	:	\033[41;30mchacha20-ietf-poly1305\033[0m"
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_l2tp(){

	clear
	username=`randusername`
	password=`randpasswd`
	mypsk=`randpsk`
	echo "#######################################################################"
	echo ""
	echo "开始配置L2TP VPN:"
	echo ""
	echo "#######################################################################"
	echo ""
	echo "请设置VPN客户端IP段:"
	read -p "(默认IP:172.16.18):" iprange
	[ -z ${iprange} ] && iprange="172.16.18"

	echo "请设置预共享密钥:"
	read -p "(默认密钥:${mypsk}):" tmppsk
	[ ! -z ${tmppsk} ] && mypsk=${tmppsk}
		
	echo "请输入用户名:"
	read -p "(默认用户名:${username}):" tmpusername
	[ ! -z ${tmpusername} ] && username=${tmpusername}
		
	echo "请输入用户${username}的密码:"
	read -p "(默认密码:${password}):" tmppassword
	[ ! -z ${tmppassword} ] && password=${tmppassword}

	echo ""
	echo "请保存好L2TP VPN的用户名密码密钥！"
	echo -e "服务器IP:	\033[41;30m${IP}\033[0m"
	echo "VPN网关IP:	${iprange}.1"
	echo "VPN客户端IP:	${iprange}.2-${iprange}.254"
	echo -e "用户名:		\033[41;30m${username}\033[0m"
	echo -e "密码:		\033[41;30m${password}\033[0m"
	echo -e "密钥:		\033[41;30m${mypsk}\033[0m"
	echo "#######################################################################"
	echo ""
	any_key_to_continue
	yum -y install ppp libreswan xl2tpd
	sysctl -p
	systemctl start ipsec
	systemctl start xl2tpd	
	systemctl enable ipsec
	systemctl enable xl2tpd

	cat > /etc/firewalld/services/xl2tpd.xml<<-EOF
	<?xml version="1.0" encoding="utf-8"?>
	<service>
	  <short>xl2tpd</short>
	  <description>L2TP IPSec</description>
	  <port protocol="udp" port="4500"/>
	  <port protocol="udp" port="1701"/>
	</service>
	EOF

	chmod 640 /etc/firewalld/services/xl2tpd.xml

	cat > /etc/ipsec.conf<<-EOF
	version 2.0

	config setup
	    protostack=netkey
	    nhelpers=0
	    uniqueids=no
	    interfaces=%defaultroute
	    virtual_private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!${iprange}.0/24

	conn l2tp-psk
	    rightsubnet=vhost:%priv
	    also=l2tp-psk-nonat

	conn l2tp-psk-nonat
	    authby=secret
	    pfs=no
	    auto=add
	    keyingtries=3
	    rekey=no
	    ikelifetime=8h
	    keylife=1h
	    type=transport
	    left=%defaultroute
	    leftid=${IP}
	    leftprotoport=17/1701
	    right=%any
	    rightprotoport=17/%any
	    dpddelay=40
	    dpdtimeout=130
	    dpdaction=clear
	    sha2-truncbug=yes
	EOF

	cat > /etc/ipsec.secrets<<-EOF
	%any %any : PSK "${mypsk}"
	EOF

	cat > /etc/xl2tpd/xl2tpd.conf<<-EOF
	[global]
	port = 1701

	[lns default]
	ip range = ${iprange}.2-${iprange}.254
	local ip = ${iprange}.1
	require chap = yes
	refuse pap = yes
	require authentication = yes
	name = l2tpd
	ppp debug = yes
	pppoptfile = /etc/ppp/options.xl2tpd
	length bit = yes
	EOF

	cat > /etc/ppp/options.xl2tpd<<-EOF
	ipcp-accept-local
	ipcp-accept-remote
	require-mschap-v2
	ms-dns 8.8.8.8
	ms-dns 8.8.4.4
	noccp
	auth
	hide-password
	idle 1800
	mtu 1410
	mru 1410
	nodefaultroute
	debug
	proxyarp
	connect-delay 5000
	EOF

	rm -f /etc/ppp/chap-secrets

	cat > /etc/ppp/chap-secrets<<-EOF
	# Secrets for authentication using CHAP
	# client    server    secret    IP addresses
	${username}    l2tpd    ${password}       *
	EOF

	firewall-cmd --reload
	firewall-cmd --permanent --add-service=ipsec
	firewall-cmd --permanent --add-service=xl2tpd
	firewall-cmd --permanent --add-masquerade
	firewall-cmd --reload
	systemctl restart ipsec
	systemctl restart xl2tpd
	systemctl -a | grep ipsec
	systemctl -a | grep xl2tpd
	cd
	wget https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/l2tp_bin.sh
	chmod +x l2tp_bin.sh
	./l2tp_bin.sh
	sleep 3
	ipsec verify
	rm -rf l2tp.sh
	echo ""
	echo "如果没有出现FAILED，说明L2TP VPN安装完毕，请测试使用是否正常."
	echo ""
	echo "#######################################################################"
	echo "L2TP VPN的相关配置:"
	echo -e "Server IP	:	\033[41;30m${IP}\033[0m"
	echo -e "预共享密钥 	:	\033[41;30m${mypsk}\033[0m"
	echo -e "Username 	:	\033[41;30m${username}\033[0m"
	echo -e "Password 	:	\033[41;30m${password}\033[0m"
	echo "#######################################################################"
	echo "请用以下命令修改L2TP VPN配置:"
	echo "l2tp -a (新增用户)"
	echo "l2tp -d (删除用户)"
	echo "l2tp -l (列出用户列表)"
	echo "l2tp -m (修改指定用户的密码)"
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_v2ray(){

	UUID=$(cat /proc/sys/kernel/random/uuid)

	v2ray_install_component(){

		local COMPONENT=$1
		COMPONENT_CMD=$(command -v $COMPONENT)

		if [ -n "${COMPONENT_CMD}" ]; then
			return
		fi

		if [ ${SOFTWARE_UPDATED} -eq 1 ]; then
			return
		fi

		if [ -n "${YUM_CMD}" ]; then
			${YUM_CMD} -q makecache
		fi

		SOFTWARE_UPDATED=1

		if [ -n "${YUM_CMD}" ]; then
			${YUM_CMD} -y -q install $COMPONENT
		fi
	}

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装V2Ray..."
	echo ""
	echo "#######################################################################"
	echo ""
	YUM_CMD=$(command -v yum)
	SOFTWARE_UPDATED=0
	V2RAY_RUNNING=0

	if pgrep "v2ray" > /dev/null ; then
		V2RAY_RUNNING=1
	fi

	VER="$(curl -s https://api.github.com/repos/v2ray/v2ray-core/releases/latest | grep 'tag_name' | cut -d\" -f4)"
	ARCH=$(uname -m)
	VDIS="64"

	if [[ "$ARCH" == "i686" ]] || [[ "$ARCH" == "i386" ]]; then
		VDIS="32"
	elif [[ "$ARCH" == *"armv7"* ]] || [[ "$ARCH" == "armv6l" ]]; then
		VDIS="arm"
	elif [[ "$ARCH" == *"armv8"* ]]; then
		VDIS="arm64"
	fi

	rm -rf /tmp/v2ray
	mkdir -p /tmp/v2ray
	DOWNLOAD_LINK="https://github.com/v2ray/v2ray-core/releases/download/${VER}/v2ray-linux-${VDIS}.zip"
	v2ray_install_component "curl"
	curl -L -H "Cache-Control: no-cache" -o "/tmp/v2ray/v2ray.zip" ${DOWNLOAD_LINK}
	v2ray_install_component "unzip"
	unzip "/tmp/v2ray/v2ray.zip" -d "/tmp/v2ray/"
	mkdir -p /var/log/v2ray
	SYSTEMCTL_CMD=$(command -v systemctl)
	mkdir -p /usr/bin/v2ray
	cp "/tmp/v2ray/v2ray-${VER}-linux-${VDIS}/v2ray" "/usr/bin/v2ray/v2ray"
	chmod +x "/usr/bin/v2ray/v2ray"
	firewall-cmd --permanent --zone=public --add-port=8888/tcp
	firewall-cmd --permanent --zone=public --add-port=8888/udp
	firewall-cmd --permanent --zone=public --add-port=8889/tcp
	firewall-cmd --permanent --zone=public --add-port=8889/udp
	firewall-cmd --reload
	mkdir -p /etc/v2ray

	if [ ! -f "/etc/v2ray/config.json" ]; then
		cp "/tmp/v2ray/v2ray-${VER}-linux-${VDIS}/vpoint_vmess_freedom.json" "/etc/v2ray/config.json"
		v2raysspw=`randusername`

	cat > /etc/v2ray/config.json<<-EOF
	{
	  "log" :
	  {
	    "access": "/var/log/v2ray/access.log",
	    "error": "/var/log/v2ray/error.log",
	    "loglevel": "warning"
	  },

	  "inbound": {
	  "address": "${IP}",
	    "port": 8888,
	    "protocol": "vmess",
	    "settings": {
	      "clients": [
	          {
	            "id": "${UUID}",
	            "level": 1,
	            "alterId": 100
	          }
	      ]
	     },
	    "streamSettings": {
	    "network": "tcp"
	    }
	  },

	"outbound": {
	    "protocol": "freedom",
	    "settings": {}
	},

	"inboundDetour": [
	    {
	      "protocol": "shadowsocks",
	      "port": 8889,
	      "settings": {
	        "method": "aes-256-cfb",
	        "password": "${v2raysspw}",
	        "udp": true
	      }
	    }
	],

	"outboundDetour": [
	    {
	      "protocol": "blackhole",
	      "settings": {},
	      "tag": "blocked"
	    }
	],

	"routing": {
	    "strategy": "rules",
	    "settings": {
	      "rules": [
	        {
	          "type": "field",
	          "ip": [
	            "0.0.0.0/8",
	            "10.0.0.0/8",
	            "100.64.0.0/10",
	            "127.0.0.0/8",
	            "169.254.0.0/16",
	            "172.16.0.0/12",
	            "192.0.0.0/24",
	            "192.0.2.0/24",
	            "192.168.0.0/16",
	            "198.18.0.0/15",
	            "198.51.100.0/24",
	            "203.0.113.0/24",
	            "::1/128",
	            "fc00::/7",
	            "fe80::/10"
	          ],
	          "outboundTag": "blocked"
	        }
	      ]
	    }
	},

	"transport": {
	  "tcpSettings": {
	    "connectionReuse": true
	  },
	  "kcpSettings": {
	    "mtu": 1300,
	    "tti": 20,
	    "uplinkCapacity": 20,
	    "downlinkCapacity": 100,
	    "congestion": false,
	    "readBufferSize": 1,
	    "writeBufferSize": 1,
	    "header": {
	      "type": "utp"
	    }
	  }
	}
	}
	EOF
	fi

	if [ -n "${SYSTEMCTL_CMD}" ]; then
		if [ ! -f "/lib/systemd/system/v2ray.service" ]; then
			cp "/tmp/v2ray/v2ray-${VER}-linux-${VDIS}/systemd/v2ray.service" "/lib/systemd/system/"
			systemctl enable v2ray
			systemctl start v2ray
			systemctl -a | grep v2ray
		fi
	fi

	echo "#######################################################################"
	echo ""
	echo "V2Ray安装完毕."
	echo ""
	echo "V2Ray的相关配置:"
	echo -e "服务器IP		:	\033[41;30m${IP}\033[0m"
	echo -e "UUID			:	\033[41;30m${UUID}\033[0m"
	echo -e "V2Ray端口		:	\033[41;30m8888\033[0m"
	echo -e "V2Ray SS端口		:	\033[41;30m8889\033[0m"
	echo -e "V2Ray SS加密方式	:	\033[41;30maes-256-cfb\033[0m"
	echo -e "V2Ray SS密码		:	\033[41;30m${v2raysspw}\033[0m"
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_supervisor(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Supervisor"
	echo ""
	echo "#######################################################################"
	echo ""
	
	SUPERVISOR_SYSTEMD_FILE_URL="https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/supervisord.systemd"

	download_file(){

		local url="$1"
		local file="$2"
		local verify="$3"
		local retry=0
		local verify_cmd=
		download_file_to_path
	}

	download_file_to_path(){

		if verify_file; then
			return 0
		fi

		if [ $retry -ge 3 ]; then
			rm -f "$file"

			cat >&2 <<-EOF
			文件下载或校验失败! 请重试。
			URL: ${url}
			EOF

			if [ -n "$verify_cmd" ]; then

				cat >&2 <<-EOF
				如果下载多次失败，你可以手动下载文件:
				1. 下载文件 ${url}
				2. 将文件重命名为 $(basename "$file")
				3. 上传文件至目录 $(dirname "$file")
				4. 重新运行安装脚本

				注: 文件目录 . 表示当前目录，.. 表示当前目录的上级目录
				EOF

			fi
			any_key_to_continue
			mainmenu
		fi

			( set -x; wget -O "$file" --no-check-certificate "$url" )

		if [ "$?" != "0" ] || [ -n "$verify_cmd" ] && ! verify_file; then
			retry=$(expr $retry + 1)
			download_file_to_path
		fi
	}

	verify_file(){

		if [ -z "$verify_cmd" ] && [ -n "$verify" ]; then
			if [ "${#verify}" = "32" ]; then
				verify_cmd="md5sum"
			elif [ "${#verify}" = "40" ]; then
				verify_cmd="sha1sum"
			elif [ "${#verify}" = "64" ]; then
				verify_cmd="sha256sum"
			elif [ "${#verify}" = "128" ]; then
				verify_cmd="sha512sum"
			fi

			if [ -n "$verify_cmd" ] && ! command_exists "$verify_cmd"; then
				verify_cmd=
			fi
		fi

		if [ -s "$file" ] && [ -n "$verify_cmd" ]; then
			(
				set -x
				echo "${verify}  ${file}" | $verify_cmd -c
			)
			return $?
		fi

		return 1
	}

	config_install_supervisor(){

		if [ ! -d /etc/supervisor/conf.d ]; then
			(
				set -x
				mkdir -p /etc/supervisor/conf.d
			)
		fi

		if [ ! -f '/usr/local/bin/supervisord' ]; then
			(
				set -x
				ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
			)
		fi

		if [ ! -f '/usr/local/bin/supervisorctl' ]; then
			(
				set -x
				ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
			)
		fi

		if [ ! -f '/usr/local/bin/pidproxy' ]; then
			(
				set -x
				ln -s "$(command -v pidproxy)" '/usr/local/bin/pidproxy' 2>/dev/null
			)
		fi

		local cfg_file='/etc/supervisor/supervisord.conf'

		if [ ! -s "$cfg_file" ]; then
			if ! command_exists echo_supervisord_conf; then

				cat >&2 <<-EOF
				未找到 echo_supervisord_conf, 无法自动创建 Supervisor 配置文件!
				可能是当前安装的 supervisor 版本过低。
				EOF

				any_key_to_continue
				mainmenu
			fi

			(
				set -x
				echo_supervisord_conf >"$cfg_file" 2>/dev/null
			)

			if [ "$?" != "0" ]; then
				echo "创建 Supervisor 配置文件失败!"
				any_key_to_continue
				mainmenu
			fi
		fi

		if ! grep -q '^files[[:space:]]*=[[:space:]]*/etc/supervisor/conf.d/\*\.conf$' "$cfg_file"; then
			if grep -q '^\[include\]$' "$cfg_file"; then
				sed -i '/^\[include\]$/a files = \/etc\/supervisor\/conf.d\/\*\.conf' "$cfg_file"
			else
				sed -i '$a [include]\nfiles = /etc/supervisor/conf.d/*.conf' "$cfg_file"
			fi
		fi
	}

	download_startup_file(){

		local supervisor_startup_file=
		local supervisor_startup_file_url=

		if command_exists systemctl; then
			supervisor_startup_file='/lib/systemd/system/supervisord.service'
			supervisor_startup_file_url="$SUPERVISOR_SYSTEMD_FILE_URL"
			download_file "$supervisor_startup_file_url" "$supervisor_startup_file"
			(
				set -x
				systemctl daemon-reload >/dev/null 2>&1
			)
		fi
	}

	if [ -s /etc/supervisord.conf ] && command_exists supervisord; then

		cat >&2 <<-EOF
		检测到你曾经通过其他方式安装过 Supervisor , 这会和本脚本安装的 Supervisor 产生冲突
		推荐你备份当前 Supervisor 配置后卸载原有版本
		已安装的 Supervisor 配置文件路径为: /etc/supervisord.conf
		通过本脚本安装的 Supervisor 配置文件路径为: /etc/supervisor/supervisord.conf
		你可以使用以下命令来备份原有配置文件:

		    mv /etc/supervisord.conf /etc/supervisord.conf.bak
		EOF

		any_key_to_continue
		mainmenu
	fi

	if [ -s /etc/supervisor/supervisord.conf ]&& command_exists supervisord;then
		config_install_supervisor
		download_startup_file
		systemctl start supervisord.service
		supervisorctl update
		supervisorctl reread
		supervisorctl status
	else
		if ! command_exists easy_install; then

			cat >&2 <<-EOF
			未找到已安装的 easy_install 命令，
			请先手动安装 python-setuptools
			然后重新运行安装脚本。
			EOF

			any_key_to_continue
			mainmenu
		fi

		if ! ( easy_install --help >/dev/null 2>&1 ); then

			cat >&2 <<-EOF
			检测到你的 easy_install 已损坏，
			通常是由于你自己升级过 python 版本，
			但是没有将 easy_install 链接到新的地址。
			需要手动做一个软链接
			 * ln -s /usr/local/python2.7/bin/easy_install /usr/bin/easy_install

			 "/usr/local/python2.7" 应该为你新版本 python 的路径
			EOF

			any_key_to_continue
			mainmenu
		fi

		(
			set -x
			easy_install -U supervisor
		)

		if [ "$?" != "0" ]; then

			cat >&2 <<-EOF
			错误: 安装 Supervisor 失败，
			请尝试使用
			  easy_install -U supervisor
			来手动安装。
			EOF

			any_key_to_continue
			mainmenu
		fi

		config_install_supervisor
		download_startup_file
		systemctl start supervisord.service
		supervisorctl update
		supervisorctl reread
		supervisorctl status
	fi

	echo "#######################################################################"
	echo ""
	echo "Supervisor安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_vlmcsd(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Vlmcsd..."
	echo ""
	echo "#######################################################################"
	echo ""
	firewall-cmd --zone=public --add-port=1688/tcp --permanent
	firewall-cmd --zone=public --add-port=1688/udp --permanent
	firewall-cmd --reload

	if [ -s /etc/init.d/vlmcsd ]; then
		/etc/init.d/vlmcsd stop
		/sbin/chkconfig --del vlmcsd
		rm -f /etc/init.d/vlmcsd
	fi

	if [ -s /usr/local/bin/vlmcsdmulti-x64-musl-static ]; then
		rm -f /usr/local/bin/vlmcsdmulti-x64-musl-static
	fi

	wget -O /usr/local/bin/vlmcsd --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/vlmcsd.server
	chmod 0755 /usr/local/bin/vlmcsd
	wget -O /usr/local/bin/vlmcsdmulti-x64-musl-static --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/vlmcsdmulti-x64-musl-static
	chmod 0755 /usr/local/bin/vlmcsdmulti-x64-musl-static

	cat > /usr/lib/systemd/system/vlmcsd.service<<-EOF
	[Unit]
	Description=Vlmcsd Server Service
	After=network.target

	[Service]
	Type=forking
	ExecStart=/usr/local/bin/vlmcsd start
	ExecStop=/usr/local/bin/vlmcsd stop
	User=root
	Group=root
	Restart=always

	[Install]
	WantedBy=multi-user.target
	EOF

	systemctl daemon-reload
	systemctl enable vlmcsd.service
	systemctl start vlmcsd.service
	systemctl -a |grep vlmcsd
	echo "#######################################################################"
	echo ""
	echo "Vlmcsd安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_kcptun(){

	SHELL_VERSION=0.1
	CONFIG_VERSION=0.1
	INIT_VERSION=0.1
	KCPTUN_INSTALL_DIR='/usr/local/kcptun'
	KCPTUN_LOG_DIR='/var/log/kcptun'
	KCPTUN_RELEASES_URL='https://api.github.com/repos/xtaci/kcptun/releases'
	KCPTUN_LATEST_RELEASE_URL="${KCPTUN_RELEASES_URL}/latest"
	KCPTUN_TAGS_URL='https://github.com/xtaci/kcptun/tags'
	SHELL_VERSION_INFO_URL="https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/version.json"
	JQ_LINUX64_URL="https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/jq-linux64"
	JQ_LINUX64_HASH='d8e36831c3c94bb58be34dd544f44a6c6cb88568'
	JQ_BIN="${KCPTUN_INSTALL_DIR}/bin/jq"	
	D_LISTEN_PORT=800
	D_TARGET_ADDR=${IP}
	D_TARGET_PORT=999
	D_KEY=`randpasswd`
	D_CRYPT='salsa20'
	D_MODE='fast3'
	D_MTU=1300
	D_SNDWND=2048
	D_RCVWND=2048
	D_DATASHARD=10
	D_PARITYSHARD=3
	D_DSCP=0
	D_NOCOMP='false'
	D_SNMPPERIOD=60
	D_PPROF='false'
	D_ACKNODELAY='false'
	D_NODELAY=1
	D_INTERVAL=20
	D_RESEND=2
	D_NC=1
	D_SOCKBUF=4194304
	D_KEEPALIVE=10
	current_instance_id=
	run_user='kcptun'

	set_snmp(){

		snmplog="$(get_current_file 'snmp')"

		local input=
		[ -z "$snmpperiod" ] && snmpperiod="$D_SNMPPERIOD"
		while :
		do
			cat >&1 <<-EOF
			请设置 SNMP 记录间隔时间 snmpperiod
			EOF

			read -p "(默认: ${snmpperiod}): " input		
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -lt 0 ]; then
					echo "输入有误, 请输入大于等于0的数字!"
					continue
				fi
				snmpperiod=$input
			fi

			break
		done

		cat >&1 <<-EOF
		---------------------------
		snmplog = ${snmplog}
		snmpperiod = ${snmpperiod}
		---------------------------
		EOF
	}

	unset_snmp(){
		snmplog=
		snmpperiod=

		cat >&1 <<-EOF
		---------------------------
		不记录 SNMP 日志
		---------------------------
		EOF
	}

	get_kcptun_server_file(){

		if [ -z "$file_suffix" ]; then
			get_arch
		fi

		echo "${KCPTUN_INSTALL_DIR}/server_$file_suffix"
	}

	show_version_and_client_url(){

		local version=
		version="$(get_installed_version)"

		if [ -n "$version" ]; then
			cat >&1 <<-EOF

			当前安装的 Kcptun 版本为: ${version}
			EOF
		fi

		if [ -n "$kcptun_release_html_url" ]; then

			cat >&1 <<-EOF
			请自行前往:
			  ${kcptun_release_html_url}
			手动下载客户端文件
			EOF
		fi
	}

	show_configs(){
		local k; local v

		for k in "$@"; do
			v="$(eval echo "\$$k")"

			if [ -n "$v" ]; then
				printf "${k}:\033[41;30m ${v} \033[0m\n"
			fi
		done
	}

	is_number(){

		expr $1 + 1 >/dev/null 2>&1
	}

	gen_client_configs(){
		local k; local v

		for k in "$@"; do
			if [ "$k" = "sndwnd" ]; then
				v="$rcvwnd"
			elif [ "$k" = "rcvwnd" ]; then
				v="$sndwnd"
			else
				v="$(eval echo "\$$k")"
			fi

			if [ -n "$v" ]; then
				if is_number "$v" || [ "$v" = "true" ] || [ "$v" = "false" ]; then
					client_config="$(echo "$client_config" | $JQ_BIN -r ".${k}=${v}")"
				else
					client_config="$(echo "$client_config" | $JQ_BIN -r ".${k}=\"${v}\"")"
				fi
			fi
		done
	}

	gen_client_configs(){
		local k; local v

		for k in "$@"; do
			if [ "$k" = "sndwnd" ]; then
				v="$rcvwnd"
			elif [ "$k" = "rcvwnd" ]; then
				v="$sndwnd"
			else
				v="$(eval echo "\$$k")"
			fi

			if [ -n "$v" ]; then
				if [ "$v" = "false" ]; then
					continue
				elif [ "$v" = "true" ]; then
					mobile_config="${mobile_config};${k}"
				else
					mobile_config="${mobile_config};${k}=${v}"
				fi
			fi
		done
	}

	show_current_instance_info(){

		wget https://raw.githubusercontent.com/aiyouwolegequ/aiyouwolegequ/master/kcptun_bin.sh
		chmod +x kcptun_bin.sh
		./kcptun_bin.sh
		local server_ip=
		server_ip="${IP}"
		clear
		echo ""
		echo "请保存好Kcptun配置！"
		echo ""
		echo "#######################################################################"
		echo ""
		printf "服务器IP:\033[41;30m ${server_ip} \033[0m\n"
		printf "端口:\033[41;30m ${listen_port} \033[0m\n"
		printf "加速地址:\033[41;30m ${target_addr}:${target_port}\033[0m\n"
		show_configs "key" "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
			"parityshard" "dscp" "nocomp" "nodelay" "interval" "resend" \
			"nc" "acknodelay" "sockbuf" "keepalive"
		show_version_and_client_url
		install_jq
		local client_config=

		read -d '' client_config <<-EOF
		{
		  "localaddr"	: "${target_port}",
		  "remoteaddr"	: "${server_ip}:${listen_port}",
		  "key"		: "${key}"
		}
		EOF

		gen_client_configs "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
			"parityshard" "dscp" "nocomp" "nodelay" "interval" "resend" \
			"nc" "acknodelay" "sockbuf" "keepalive"

		cat >&1 <<-EOF
		可使用的客户端配置文件为:
		${client_config}
		EOF

		echo ""
		echo "#######################################################################"
		local mobile_config="key=${key}"
		gen_client_configs "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
			"parityshard" "dscp" "nocomp" "nodelay" "interval" "resend" \
			"nc" "acknodelay" "sockbuf" "keepalive"

		cat >&1 <<-EOF
		手机端参数可以使用:
		  ${mobile_config}
		EOF
	}

	set_manual_parameters(){

		echo "开始配置手动参数..."
		local input=
		local yn=
		[ -z "$nodelay" ] && nodelay="$D_NODELAY"

		while :
		do
			cat >&1 <<-EOF
			是否启用 nodelay 模式?
			(0) 不启用
			(1) 启用
			EOF

			read -p "(默认: ${nodelay}) [0/1]: " input
			if [ -n "$input" ]; then
				case "${input:0:1}" in
					1)
						nodelay=1
						;;
					0|*)
						nodelay=0
						;;
					*)
						echo "输入有误，请重新输入!"
						continue
						;;
				esac
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		nodelay = ${nodelay}
		---------------------------
		EOF

		[ -z "$interval" ] && interval="$D_INTERVAL"
		while :
		do
			cat >&1 <<-EOF
			请设置协议内部工作的 interval
			EOF

			read -p "(单位: ms, 默认: ${interval}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -le 0 ]; then
					echo "输入有误, 请输入大于0的数字!"
					continue
				fi

				interval=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		interval = ${interval}
		---------------------------
		EOF

		[ -z "$resend" ] && resend="$D_RESEND"
		while :
		do
			cat >&1 <<-EOF
			是否启用快速重传模式(resend)?
			(0) 不启用
			(1) 启用
			(2) 2次ACK跨越将会直接重传
			EOF

			read -p "(默认: ${resend}) 请选择 [0~2]: " input
			if [ -n "$input" ]; then
				case "${input:0:1}" in
					0)
						resend=0
						;;
					1)
						resend=1
						;;
					2)
						resend=2
						;;
					*)
						echo "输入有误，请重新输入!"
						continue
						;;
				esac
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		resend = ${resend}
		---------------------------
		EOF

		[ -z "$nc" ] && nc="$D_NC"
		while :
		do
			cat >&1 <<-EOF
			是否关闭流控(nc)?
			(0) 关闭
			(1) 开启
			EOF

			read -p "(默认: ${nc}) [0/1]: " input
			if [ -n "$input" ]; then
				case "${input:0:1}" in
					0)
						nc=0
						;;
					1)
						nc=1
						;;
					*)
						echo "输入有误，请重新输入!"
						continue
						;;
				esac
			fi

			break
		done

		cat >&1 <<-EOF
		---------------------------
		nc = ${nc}
		---------------------------
		EOF
	}



	download_file_to_path(){

		if verify_file; then
			return 0
		fi

		if [ $retry -ge 3 ]; then
			rm -f "$file"

			cat >&2 <<-EOF
			文件下载或校验失败! 请重试。
			URL: ${url}
			EOF

			if [ -n "$verify_cmd" ]; then

				cat >&2 <<-EOF
				如果下载多次失败，你可以手动下载文件:
				1. 下载文件 ${url}
				2. 将文件重命名为 $(basename "$file")
				3. 上传文件至目录 $(dirname "$file")
				4. 重新运行安装脚本

				注: 文件目录 . 表示当前目录，.. 表示当前目录的上级目录
				EOF
			fi

			any_key_to_continue
			mainmenu
		fi

			( set -x; wget -O "$file" --no-check-certificate "$url" )

		if [ "$?" != "0" ] || [ -n "$verify_cmd" ] && ! verify_file; then
			retry=$(expr $retry + 1)
			download_file_to_path
		fi
	}

	verify_file(){

		if [ -z "$verify_cmd" ] && [ -n "$verify" ]; then
			if [ "${#verify}" = "32" ]; then
				verify_cmd="md5sum"
			elif [ "${#verify}" = "40" ]; then
				verify_cmd="sha1sum"
			elif [ "${#verify}" = "64" ]; then
				verify_cmd="sha256sum"
			elif [ "${#verify}" = "128" ]; then
				verify_cmd="sha512sum"
			fi

			if [ -n "$verify_cmd" ] && ! command_exists "$verify_cmd"; then
				verify_cmd=
			fi
		fi

		if [ -s "$file" ] && [ -n "$verify_cmd" ]; then
			(
				set -x
				echo "${verify}  ${file}" | $verify_cmd -c
			)
			return $?
		fi

		return 1
	}

	download_file(){

		local url="$1"
		local file="$2"
		local verify="$3"
		local retry=0
		local verify_cmd=

		download_file_to_path
	}

	get_arch(){

		architecture=$(uname -m)
		case "$architecture" in
			amd64|x86_64)
				spruce_type='linux-amd64'
				file_suffix='linux_amd64'
				;;
			i386|i486|i586|i686|x86)
				spruce_type='linux-386'
				file_suffix='linux_386'
				;;
			*)
				cat 1>&2 <<-EOF
				当前脚本仅支持 32 位 和 64 位系统
				你的系统为: $architecture
				EOF
				any_key_to_continue
				mainmenu
				;;
		esac
	}

	check_jq(){

		if [ ! -f "$JQ_BIN" ]; then
			return 1
		fi

		[ ! -x "$JQ_BIN" ] && chmod a+x "$JQ_BIN"

		if ( $JQ_BIN --help 2>/dev/null | grep -q "JSON" ); then
			is_checkd_jq="true"
			return 0
		else
			rm -f "$JQ_BIN"
			return 1
		fi
	}

	install_jq(){

		if [ -z "$is_checkd_jq" ] && ! check_jq; then
			local dir=
			dir="$(dirname "$JQ_BIN")"

			if [ ! -d "$dir" ]; then
				(
					set -x
					mkdir -p "$dir"
				)
			fi

			if [ -z "$architecture" ]; then
				get_arch

			fi

			case "$architecture" in
				amd64|x86_64)
					download_file "$JQ_LINUX64_URL" "$JQ_BIN" "$JQ_LINUX64_HASH"
					;;
			esac

			if ! check_jq; then

				cat >&2 <<-EOF
				未找到适用于当前系统的 JSON 解析软件 jq
				EOF
				any_key_to_continue
				mainmenu
			fi

			return 0

		fi
	}

	is_port(){

		local port=$1
		is_number "$port" && \
			[ $port -ge 1 ] && [ $port -le 65535 ]
	}

	port_using(){

		local port=$1

		if command_exists netstat; then
			( netstat -ntul | grep -qE "[0-9:]:${port}\s" )
		elif command_exists ss; then
			( ss -ntul | grep -qE "[0-9:]:${port}\s" )
		else
			return 0
		fi

		return $?
	}

	unset_hidden_parameters(){

		acknodelay=
		sockbuf=
		keepalive=

		cat >&1 <<-EOF
		---------------------------
		不配置隐藏参数
		---------------------------
		EOF
	}

	set_kcptun_config(){

		local input=
		local yn=
		[ -z "$listen_port" ] && listen_port="$D_LISTEN_PORT"

		while :
		do
			cat >&1 <<-EOF
			请输入 Kcptun 服务端运行端口 [1~65535]
			这个端口就是 Kcptun 客户端连接的端口
			EOF

			read -p "(默认: ${listen_port}): " input
			if [ -n "$input" ]; then
				if is_port "$input"; then
					listen_port="$input"
				else
					echo "输入有误, 请输入 1~65535 之间的数字!"
					continue
				fi
			fi

			if port_using "$listen_port" && \
				[ "$listen_port" != "$current_listen_port" ]; then
				echo "端口已被占用, 请重新输入!"
				continue
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		端口 = ${listen_port}
		---------------------------
		EOF

		[ -z "$target_addr" ] && target_addr="$D_TARGET_ADDR"

		cat >&1 <<-EOF
		请输入需要加速的地址
		可以输入主机名称、IPv4 地址或者 IPv6 地址
		EOF

		read -p "(默认: ${target_addr}): " input
		if [ -n "$input" ]; then
			target_addr="$input"
		fi

		input=

		cat >&1 <<-EOF
		---------------------------
		加速地址 = ${target_addr}
		---------------------------
		EOF

		[ -z "$target_port" ] && target_port="$D_TARGET_PORT"
		while :
		do
			cat >&1 <<-EOF
			请输入需要加速的端口 [1~65535]
			EOF

			read -p "(默认: ${target_port}): " input
			if [ -n "$input" ]; then
				if is_port "$input"; then
					if [ "$input" = "$listen_port" ]; then
						echo "加速端口不能和 Kcptun 端口一致!"
						continue
					fi

					target_port="$input"
				else
					echo "输入有误, 请输入 1~65535 之间的数字!"
					continue
				fi
			fi

			if [ "$target_addr" = "127.0.0.1" ] && ! port_using "$target_port"; then
				read -p "当前没有软件使用此端口, 确定加速此端口? [y/n]: " yn
				if [ -n "$yn" ]; then
					case "${yn:0:1}" in
						y|Y)
							;;
						*)
							continue
							;;
					esac
				fi
			fi

			break
		done

		input=
		yn=

		cat >&1 <<-EOF
		---------------------------
		加速端口 = ${target_port}
		---------------------------
		EOF

		[ -z "$key" ] && key="$D_KEY"

		cat >&1 <<-EOF
		请设置 Kcptun 密码(key)
		该参数必须两端一致
		EOF

		read -p "(默认密码: ${key}): " input
		[ -n "$input" ] && key="$input"

		input=

		cat >&1 <<-EOF
		---------------------------
		密码 = ${key}
		---------------------------
		EOF

		[ -z "$crypt" ] && crypt="$D_CRYPT"
		local crypt_list="aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor none"
		local i=0

		cat >&1 <<-EOF
		请选择加密方式(crypt)
		强加密对 CPU 要求较高，
		如果是在路由器上配置客户端，
		请尽量选择弱加密或者不加密。
		该参数必须两端一致
		EOF

		while :
		do

			for c in $crypt_list; do
				i=$(expr $i + 1)
				echo "(${i}) ${c}"
			done

			read -p "(默认: ${crypt}) 请选择 [1~$i]: " input
			if [ -n "$input" ]; then
				if is_number "$input" && [ $input -ge 1 ] && [ $input -le $i ]; then
					crypt=$(echo "$crypt_list" | cut -d' ' -f ${input})
				else
					echo "请输入有效数字 1~$i!"
					i=0
					continue
				fi
			fi

			break
		done

		input=
		i=0

		cat >&1 <<-EOF
		-----------------------------
		加密方式 = ${crypt}
		-----------------------------
		EOF

		[ -z "$mode" ] && mode="$D_MODE"
		local mode_list="normal fast fast2 fast3 manual"
		i=0

		cat >&1 <<-EOF
		请选择加速模式(mode)
		加速模式和发送窗口大小共同决定了流量的损耗大小
		如果加速模式选择“手动(manual)”，
		将进入手动档隐藏参数的设置。
		EOF

		while :
		do

			for m in $mode_list; do
				i=$(expr $i + 1)
				echo "(${i}) ${m}"
			done

			read -p "(默认: ${mode}) 请选择 [1~$i]: " input
			if [ -n "$input" ]; then
				if is_number "$input" && [ $input -ge 1 ] && [ $input -le $i ]; then
					mode=$(echo "$mode_list" | cut -d ' ' -f ${input})
				else
					echo "请输入有效数字 1~$i!"
					i=0
					continue
				fi
			fi

			break
		done

		input=
		i=0

		cat >&1 <<-EOF
		---------------------------
		加速模式 = ${mode}
		---------------------------
		EOF

		if [ "$mode" = "manual" ]; then
			set_manual_parameters
		else
			nodelay=
			interval=
			resend=
			nc=
		fi

		[ -z "$mtu" ] && mtu="$D_MTU"

		while :
		do
			cat >&1 <<-EOF
			请设置 UDP 数据包的 MTU (最大传输单元)值
			EOF

			read -p "(默认: ${mtu}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -le 0 ]; then
					echo "输入有误, 请输入大于0的数字!"
					continue
				fi

				mtu=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		MTU = ${mtu}
		---------------------------
		EOF

		[ -z "$sndwnd" ] && sndwnd="$D_SNDWND"

		while :
		do
			cat >&1 <<-EOF
			请设置发送窗口大小(sndwnd)
			发送窗口过大会浪费过多流量
			EOF

			read -p "(数据包数量, 默认: ${sndwnd}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -le 0 ]; then
					echo "输入有误, 请输入大于0的数字!"
					continue
				fi

				sndwnd=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		sndwnd = ${sndwnd}
		---------------------------
		EOF

		[ -z "$rcvwnd" ] && rcvwnd="$D_RCVWND"

		while :
		do
			cat >&1 <<-EOF
			请设置接收窗口大小(rcvwnd)
			EOF

			read -p "(数据包数量, 默认: ${rcvwnd}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -le 0 ]; then
					echo "输入有误, 请输入大于0的数字!"
					continue
				fi

				rcvwnd=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		rcvwnd = ${rcvwnd}
		---------------------------
		EOF

		[ -z "$datashard" ] && datashard="$D_DATASHARD"

		while :
		do
			cat >&1 <<-EOF
			请设置前向纠错 datashard
			该参数必须两端一致
			EOF

			read -p "(默认: ${datashard}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -lt 0 ]; then
					echo "输入有误, 请输入大于等于0的数字!"
					continue
				fi

				datashard=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		datashard = ${datashard}
		---------------------------
		EOF

		[ -z "$parityshard" ] && parityshard="$D_PARITYSHARD"

		while :
		do
			cat >&1 <<-EOF
			请设置前向纠错 parityshard
			该参数必须两端一致
			EOF

			read -p "(默认: ${parityshard}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -lt 0 ]; then
					echo "输入有误, 请输入大于等于0的数字!"
					continue
				fi

				parityshard=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		parityshard = ${parityshard}
		---------------------------
		EOF

		[ -z "$dscp" ] && dscp="$D_DSCP"

		while :
		do
			cat >&1 <<-EOF
			请设置差分服务代码点(DSCP)
			EOF

			read -p "(默认: ${dscp}): " input
			if [ -n "$input" ]; then
				if ! is_number "$input" || [ $input -lt 0 ]; then
					echo "输入有误, 请输入大于等于0的数字!"
					continue
				fi

				dscp=$input
			fi

			break
		done

		input=

		cat >&1 <<-EOF
		---------------------------
		DSCP = ${dscp}
		---------------------------
		EOF

		[ -z "$nocomp" ] && nocomp="$D_NOCOMP"

		while :
		do
			cat >&1 <<-EOF
			是否关闭数据压缩?
			EOF

			read -p "(默认: ${nocomp}) [y/n]: " yn
			if [ -n "$yn" ]; then
				case "${yn:0:1}" in
					y|Y)
						nocomp='true'
						;;
					n|N)
						nocomp='false'
						;;
					*)
						echo "输入有误，请重新输入!"
						continue
						;;
				esac
			fi

			break
		done

		yn=

		cat >&1 <<-EOF
		---------------------------
		nocomp = ${nocomp}
		---------------------------
		EOF

		cat >&1 <<-EOF
		是否记录 SNMP 日志?
		EOF

		read -p "(默认: 否) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "${yn:0:1}" in
				y|Y)
					set_snmp
					;;
				n|N|*)
					unset_snmp
					;;
			esac
			yn=
		else
			unset_snmp
		fi

		[ -z "$pprof" ] && pprof="$D_PPROF"

		while :
		do
			cat >&1 <<-EOF
			是否开启 pprof 性能监控?
			地址: http://IP:6060/debug/pprof/
			EOF

			read -p "(默认: ${pprof}) [y/n]: " yn
			if [ -n "$yn" ]; then
				case "${yn:0:1}" in
					y|Y)
						pprof='true'
						;;
					n|N)
						pprof='false'
						;;
					*)
						echo "输入有误，请重新输入!"
						continue
						;;
				esac
			fi

			break
		done

		yn=

		cat >&1 <<-EOF
		---------------------------
		pprof = ${pprof}
		---------------------------
		EOF


		cat >&1 <<-EOF
		基础参数设置完成，是否设置额外的隐藏参数?
		通常情况下保持默认即可，不用额外设置
		EOF

		read -p "(默认: 否) [y/n]: " yn
		if [ -n "$yn" ]; then
			case "${yn:0:1}" in
				y|Y)
					set_hidden_parameters
					;;
				n|N|*)
					unset_hidden_parameters
					;;
			esac
		else
			unset_hidden_parameters
		fi

		if [ $listen_port -le 1024 ]; then
			run_user="root"
		fi

		echo "配置完成。"
		echo "---------------------------"
		any_key_to_continue
	}

	install_deps(){

		if ! command_exists wget; then
			( set -x; sleep 3; yum -y -q install wget ca-certificates )
		fi

		if ! command_exists awk; then
			( set -x; sleep 3; yum -y -q install gawk )
		fi

		if ! command_exists tar; then
			( set -x; sleep 3; yum -y -q install tar )
		fi

		if ! command_exists easy_install; then
			( set -x; sleep 3; yum -y -q install python-setuptools )
		fi

		install_jq
	}

	get_kcptun_version_info(){

		local request_version=$1
		local version_content=

		if [ -n "$request_version" ]; then
			local json_content=
			json_content="$(get_content "$KCPTUN_RELEASES_URL")"
			version_content="$(get_json_string "$json_content" ".[] | select(.tag_name == \"${request_version}\")")"
		else
			version_content="$(get_content "$KCPTUN_LATEST_RELEASE_URL")"
		fi

		if [ -z "$version_content" ]; then
			return 1
		fi

		if [ -z "$spruce_type" ]; then
			get_arch
		fi

		kcptun_release_download_url="$(get_json_string "$version_content" ".assets[] | select(.name | contains(\"$spruce_type\")) | .browser_download_url")"

		if [ -z "$kcptun_release_download_url" ]; then
			return 1
		fi

		kcptun_release_tag_name="$(get_json_string "$version_content" '.tag_name')"
		kcptun_release_name="$(get_json_string "$version_content" '.name')"
		kcptun_release_prerelease="$(get_json_string "$version_content" '.prerelease')"
		kcptun_release_publish_time="$(get_json_string "$version_content" '.published_at')"
		kcptun_release_html_url="$(get_json_string "$version_content" '.html_url')"
		local body=
		body="$(get_json_string "$version_content" '.body' | grep -vE '(^```)|(^>)|(^[[:space:]]*$)')"
		kcptun_release_body="$(echo "$body" | grep -vE "[0-9a-zA-Z]{32,}")"
		local file_verify=
		file_verify="$(echo "$body" | grep "$spruce_type")"

		if [ -n "$file_verify" ]; then
			local i=1
			local split=

			while :
			do
				split="$(echo "$file_verify" | cut -d ' ' -f$i)"

				if [ -n "$split" ] && ( echo "$split" | grep -qE "^[0-9a-zA-Z]{32,}$" ); then
					kcptun_release_verify="$split"
					break
				elif [ -z "$split" ]; then
					break
				fi

				i=$(expr $i + 1)
			done
		fi

		return 0
	}

	kcptun_install(){

		if [ -z "$kcptun_release_download_url" ]; then
			get_kcptun_version_info $1

			if [ "$?" != "0" ]; then

				cat >&2 <<-EOF
				获取 Kcptun 版本信息或下载地址失败!
				可能是 GitHub 改版，或者从网络获取到的内容不正确。
				请联系脚本作者。
				EOF

				any_key_to_continue
				mainmenu
			fi
		fi

		local kcptun_file_name="kcptun-${kcptun_release_tag_name}.tar.gz"
		download_file "$kcptun_release_download_url" "$kcptun_file_name" "$kcptun_release_verify"

		if [ ! -d "$KCPTUN_INSTALL_DIR" ]; then
			(
				set -x
				mkdir -p "$KCPTUN_INSTALL_DIR"
			)
		fi

		if [ ! -d "$KCPTUN_LOG_DIR" ]; then
			(
				set -x
				mkdir -p "$KCPTUN_LOG_DIR"
				chmod a+w "$KCPTUN_LOG_DIR"
			)
		fi

		(
			set -x
			tar -zxf "$kcptun_file_name" -C "$KCPTUN_INSTALL_DIR"
			sleep 3
		)

		local kcptun_server_file=
		kcptun_server_file="$(get_kcptun_server_file)"

		if [ ! -f "$kcptun_server_file" ]; then

			cat >&2 <<-EOF
			未在解压文件中找到 Kcptun 服务端执行文件!
			通常这不会发生，可能的原因是 Kcptun 作者打包文件的时候更改了文件名。
			你可以尝试重新安装，或者联系脚本作者。
			EOF

			any_key_to_continue
			mainmenu
		fi

		chmod a+x "$kcptun_server_file"

		if [ -z "$(get_installed_version)" ]; then

			cat >&2 <<-EOF
			无法找到适合当前服务器的 kcptun 可执行文件
			你可以尝试从源码编译。
			EOF

			any_key_to_continue
			mainmenu
		fi

		rm -f "$kcptun_file_name" "${KCPTUN_INSTALL_DIR}/client_$file_suffix"
	}

	get_network_content(){

		if [ $retry -ge 3 ]; then

			cat >&2 <<-EOF
			获取网络信息失败!
			URL: ${url}
			安装脚本需要能访问到 github.com，请检查服务器网络。
			注意: 一些国内服务器可能无法正常访问 github.com。
			EOF

			any_key_to_continue
			mainmenu
		fi

		content="$(wget -qO- --no-check-certificate "$url")"

		if [ "$?" != "0" ] || [ -z "$content" ]; then
			retry=$(expr $retry + 1)
			get_network_content
		fi
	}

	get_content(){

		local url="$1"
		local retry=0
		local content=
		get_network_content
		echo "$content"
	}

	get_current_file() {

		case "$1" in
			config)
				printf '%s/server-config%s.json' "$KCPTUN_INSTALL_DIR" "$current_instance_id"
				;;
			log)
				printf '%s/server%s.log' "$KCPTUN_LOG_DIR" "$current_instance_id"
				;;
			snmp)
				printf '%s/snmplog%s.log' "$KCPTUN_LOG_DIR" "$current_instance_id"
				;;
			supervisor)
				printf '/etc/supervisor/conf.d/kcptun%s.conf' "$current_instance_id"
				;;
		esac
	}

	get_json_string(){

		install_jq
		local content="$1"
		local selector="$2"
		local regex="$3"
		local str=

		if [ -n "$content" ]; then
			str="$(echo "$content" | $JQ_BIN -r "$selector" 2>/dev/null)"

			if [ -n "$str" ] && [ -n "$regex" ]; then
				str="$(echo "$str" | grep -oE "$regex")"
			fi
		fi

		echo "$str"
	}

	get_installed_version(){

		local server_file=
		server_file="$(get_kcptun_server_file)"

		if [ -f "$server_file" ]; then
			if [ ! -x "$server_file" ]; then
				chmod a+x "$server_file"
			fi

			echo "$(${server_file} -v 2>/dev/null | awk '{printf $3}')"
		fi
	}

	config_install_supervisor(){

		if [ ! -d /etc/supervisor/conf.d ]; then
			(
				set -x
				mkdir -p /etc/supervisor/conf.d
			)
		fi

		if [ ! -f '/usr/local/bin/supervisord' ]; then
			(
				set -x
				ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
			)
		fi

		if [ ! -f '/usr/local/bin/supervisorctl' ]; then
			(
				set -x
				ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
			)
		fi

		if [ ! -f '/usr/local/bin/pidproxy' ]; then
			(
				set -x
				ln -s "$(command -v pidproxy)" '/usr/local/bin/pidproxy' 2>/dev/null
			)
		fi

		local cfg_file='/etc/supervisor/supervisord.conf'

		if [ ! -s "$cfg_file" ]; then
			if ! command_exists echo_supervisord_conf; then

				cat >&2 <<-EOF
				未找到 echo_supervisord_conf, 无法自动创建 Supervisor 配置文件!
				可能是当前安装的 supervisor 版本过低。
				EOF

				any_key_to_continue
				mainmenu
			fi

			(
				set -x
				echo_supervisord_conf >"$cfg_file" 2>/dev/null
			)

			if [ "$?" != "0" ]; then
				echo "创建 Supervisor 配置文件失败!"
				any_key_to_continue
				mainmenu
			fi
		fi

		if ! grep -q '^files[[:space:]]*=[[:space:]]*/etc/supervisor/conf.d/\*\.conf$' "$cfg_file"; then
			if grep -q '^\[include\]$' "$cfg_file"; then
				sed -i '/^\[include\]$/a files = \/etc\/supervisor\/conf.d\/\*\.conf' "$cfg_file"
			else
				sed -i '$a [include]\nfiles = /etc/supervisor/conf.d/*.conf' "$cfg_file"
			fi
		fi
	}

	mk_file_dir(){

		local dir=
		dir="$(dirname $1)"
		local mod=$2

		if [ ! -d "$dir" ]; then
			(
				set -x
				mkdir -p "$dir"
			)
		fi

		if [ -n "$mod" ]; then
			chmod $mod "$dir"
		fi
	}

	write_configs_to_file(){
		install_jq
		local k; local v
		local json=
		json="$(cat "$config_file")"

		for k in "$@"; do
			v="$(eval echo "\$$k")"

			if [ -n "$v" ]; then
				if is_number "$v" || [ "$v" = "false" ] || [ "$v" = "true" ]; then
					json="$(echo "$json" | $JQ_BIN ".$k=$v")"
				else
					json="$(echo "$json" | $JQ_BIN ".$k=\"$v\"")"
				fi
			fi
		done

		if [ -n "$json" ] && [ "$json" != "$(cat "$config_file")" ]; then
			echo "$json" >"$config_file"
		fi
	}

	gen_kcptun_config(){

		local config_file=
		config_file="$(get_current_file 'config')"
		local supervisor_config_file=
		supervisor_config_file="$(get_current_file 'supervisor')"
		mk_file_dir "$config_file"
		mk_file_dir "$supervisor_config_file"

		if [ -n "$snmplog" ]; then
			mk_file_dir "$snmplog" '777'
		fi

		if ( echo "$listen_addr" | grep -q ":" ); then
			listen_addr="[${listen_addr}]"
		fi

		if ( echo "$target_addr" | grep -q ":" ); then
			target_addr="[${target_addr}]"
		fi

		cat > "$config_file"<<-EOF
		{
		  "listen": "${listen_addr}:${listen_port}",
		  "target": "${target_addr}:${target_port}",
		  "key": "${key}",
		  "crypt": "${crypt}",
		  "mode": "${mode}",
		  "mtu": ${mtu},
		  "sndwnd": ${sndwnd},
		  "rcvwnd": ${rcvwnd},
		  "datashard": ${datashard},
		  "parityshard": ${parityshard},
		  "dscp": ${dscp},
		  "nocomp": ${nocomp}
		}
		EOF

		write_configs_to_file "snmplog" "snmpperiod" "pprof" "acknodelay" "nodelay" \
			"interval" "resend" "nc" "sockbuf" "keepalive"

		if ! grep -q "^${run_user}:" '/etc/passwd'; then
			(
				set -x
				useradd -U -s '/usr/sbin/nologin' -d '/nonexistent' "$run_user" 2>/dev/null
			)
		fi

		cat > "$supervisor_config_file"<<-EOF
		[program:kcptun${current_instance_id}]
		user=${run_user}
		directory=${KCPTUN_INSTALL_DIR}
		command=$(get_kcptun_server_file) -c "${config_file}"
		process_name=%(program_name)s
		autostart=true
		redirect_stderr=true
		stdout_logfile=$(get_current_file 'log')
		stdout_logfile_maxbytes=1MB
		stdout_logfile_backups=0
		EOF
	}

	set_firewall(){

		if command_exists firewall-cmd; then
			if ! ( firewall-cmd --state >/dev/null 2>&1 ); then
				systemctl start firewalld >/dev/null 2>&1
			fi

			if [ "$?" = "0" ]; then
				if [ -n "$current_listen_port" ]; then
					firewall-cmd --zone=public --remove-port=${current_listen_port}/udp >/dev/null 2>&1
				fi

				if ! firewall-cmd --quiet --zone=public --query-port=${listen_port}/udp; then
					firewall-cmd --quiet --permanent --zone=public --add-port=${listen_port}/udp
					firewall-cmd --reload
				fi
			else

				cat >&1 <<-EOF
				警告: 自动添加 firewalld 规则失败
				如果有必要, 请手动添加端口 ${listen_port} 的防火墙规则:
				    firewall-cmd --permanent --zone=public --add-port=${listen_port}/udp
				    firewall-cmd --reload
				EOF
			fi
		elif command_exists iptables; then
			if ! ( service iptables status >/dev/null 2>&1 ); then
				service iptables start >/dev/null 2>&1
			fi

			if [ "$?" = "0" ]; then
				if [ -n "$current_listen_port" ]; then
					iptables -D INPUT -p udp --dport ${current_listen_port} -j ACCEPT >/dev/null 2>&1
				fi

				if ! iptables -C INPUT -p udp --dport ${listen_port} -j ACCEPT >/dev/null 2>&1; then
					iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT >/dev/null 2>&1
					service iptables save
					service iptables restart
				fi
			else

				cat >&1 <<-EOF
				警告: 自动添加 iptables 规则失败
				如有必要, 请手动添加端口 ${listen_port} 的防火墙规则:
				    iptables -I INPUT -p udp --dport ${listen_port} -j ACCEPT
				    service iptables save
				    service iptables restart
				EOF
			fi
		fi
	}

	start_supervisor(){

		( set -x; sleep 3 )

		if command_exists systemctl; then
			if systemctl status supervisord.service >/dev/null 2>&1; then
				systemctl restart supervisord.service
			else
				systemctl start supervisord.service
			fi
		elif command_exists service; then
			if service supervisord status >/dev/null 2>&1; then
				service supervisord restart
			else
				service supervisord start
			fi
		fi

		if [ "$?" != "0" ]; then

			cat >&2 <<-EOF
			启动 Supervisor 失败, Kcptun 无法正常工作!
			请反馈给脚本作者。
			EOF

			any_key_to_continue
			mainmenu
		fi
	}

	enable_supervisor(){

		if command_exists systemctl; then
			(
				set -x
				systemctl enable "supervisord.service"
				supervisorctl update
				supervisorctl reread
				supervisorctl status
			)
		fi
	}

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Kcptun"
	echo ""
	echo "#######################################################################"
	echo ""
	set_kcptun_config
	install_deps
	kcptun_install

	if [ ! -e /usr/lib/systemd/system/supervisord.service ]; then
		install_supervisor
	fi

	gen_kcptun_config
	set_firewall
	start_supervisor
	enable_supervisor
	show_current_instance_info >> kcptun.log
	echo "#######################################################################"
	echo ""
	echo "Kcptun安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_dnscrypt(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Dnscrypt"
	echo ""
	echo "#######################################################################"
	echo ""
	dnscrypt=`randusername`
	wget https://download.dnscrypt.org/dnscrypt-proxy/LATEST.tar.gz -O dnscrypt-latest.tar.gz
	tar zxf dnscrypt-latest.tar.gz
	cd dnscrypt-proxy-*
	./autogen.sh
	sleep 1
	./configure
	sleep 1
	make -j4 && make install
	git clone --recursive git://github.com/cofyc/dnscrypt-wrapper.git
	cd dnscrypt-wrapper
	make configure
	sleep 1
	./configure
	sleep 1
	make install
	cd
	rm -rf dnscrypt-*
	mkdir ~/.dns
	cd ~/.dns
	dnscrypt-wrapper --gen-provider-keypair >> dns.log
	pub=$(cat dns.log | grep provider-key | awk '{print $3}' | cut -d "=" -f 2)
	dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=${dnscrypt}.key
	dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=${dnscrypt}.key --provider-cert-file=${dnscrypt}.cert --provider-publickey-file=public.key --provider-secretkey-file=secret.key --cert-file-expire-days=365
	firewall-cmd --permanent --zone=public --add-port=5553/tcp
	firewall-cmd --permanent --zone=public --add-port=5553/udp
	firewall-cmd --reload

	if [ ! -e /usr/lib/systemd/system/supervisord.service ]; then
		install_supervisor
	fi

	clear

	cat > /etc/supervisor/conf.d/dnscrypt.conf<<-EOF
	[program:dnscrypt]
	command = /usr/local/sbin/dnscrypt-wrapper --resolver-address=8.8.8.8:53 --listen-address=0.0.0.0:5553 --provider-name=1.dnscrypt-cert.${dnscrypt}.org --crypt-secretkey-file=/root/.dns/${dnscrypt}.key --provider-cert-file=/root/.dns/${dnscrypt}.cert
	startsecs = 5
	autostart = true
	startretries = 3
	user = root
	EOF

	systemctl restart supervisord.service
	supervisorctl update
	supervisorctl reread
	supervisorctl status
	echo "#######################################################################"
	echo "如需使用dnscrypt可在电脑上使用以下命令:"
	echo -e "\033[41;30mdnscrypt-proxy --local-address=127.0.0.1:53 \ \n --provider-key=$pub \ \n --resolver-address=$IP:5553 \ \n --provider-name=2.dnscrypt-cert.${dnscrypt}.org -d\033[0m"
	echo "#######################################################################"
	echo ""
	echo "Dnscrypt安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

clearsystem(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始清理系统"
	echo ""
	echo "#######################################################################"
	cd
	rm -rf kcptun_bin.sh l2tp_bin.sh
	yum autoremove
	yum makecache
	yum-complete-transaction --cleanup-only
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm -Va --nofiles --nodigest
	yum clean all
	rm -rf /var/cache/yum
	rpm --rebuilddb
	yum update -y
	echo "#######################################################################"
	echo ""
	echo "清理完毕！"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_all(){

	clear
	tunavailable
	updatesystem
	updatekernel
	changerootpasswd
	add_newuser
	install_ckrootkit_rkhunter
	install_fail2ban
	install_lynis
	install_zsh
	install_shadowsocks
	install_l2tp
	install_v2ray
	install_supervisor
	install_vlmcsd
	install_kcptun
	install_dnscrypt
	clearsystem
	finally
}

finally(){

	clear
	echo "#######################################################################"
	echo ""
	echo "搞定了，搞定了，搞定了!"
	echo "要查看刚刚的配置就按任意键继续，否则按Ctrl+C退出脚本."
	echo ""
	echo "#######################################################################"
	echo ""
	char=`get_char`
	echo "请保存好以下配置："
	echo ""
	echo "可以使用ssh登陆系统的用户:"
	echo -e "新用户名 	:	\033[41;30m${newusername}\033[0m" 
	echo -e "新用户密码 	:	\033[41;30m${newuserpasswd}\033[0m" 
	echo -e "root密码 	:	\033[41;30m${newrootpasswd}\033[0m"
	echo ""
	echo "Shadowsocks的相关配置:"
	echo -e "服务器IP	:	\033[41;30m${IP}\033[0m"
	echo -e "端口		:	\033[41;30m999\033[0m"
	echo -e "密码		:	\033[41;30m${sspasswd}\033[0m"
	echo -e "加密方式	:	\033[41;30mchacha20-ietf-poly1305\033[0m"
	echo ""
	echo "L2TP VPN的相关配置:"
	echo -e "Server IP	:	\033[41;30m${IP}\033[0m"
	echo -e "预共享密钥 	:	\033[41;30m${mypsk}\033[0m"
	echo -e "Username 	:	\033[41;30m${username}\033[0m"
	echo -e "Password 	:	\033[41;30m${password}\033[0m"
	echo ""
	echo "使用以下命令配置l2tp用户:"
	echo -e "\033[41;30ml2tp -a\033[0m (新建用户)"
	echo -e "\033[41;30ml2tp -d\033[0m (删除用户)"
	echo -e "\033[41;30ml2tp -l\033[0m (列出用户)"
	echo -e "\033[41;30ml2tp -m\033[0m (修改指定用户的密码)"
	echo ""
	echo "V2Ray的相关配置:"
	echo -e "服务器IP		:	\033[41;30m${IP}\033[0m"
	echo -e "UUID			:	\033[41;30m${UUID}\033[0m"
	echo -e "V2Ray端口		:	\033[41;30m8888\033[0m"
	echo -e "V2Ray SS端口		:	\033[41;30m8889\033[0m"
	echo -e "V2Ray SS加密方式	:	\033[41;30maes-256-cfb\033[0m"
	echo -e "V2Ray SS密码		:	\033[41;30m${v2raysspw}\033[0m"
	echo ""
	echo "如需使用dnscrypt可在电脑上使用以下命令:"
	echo -e "\033[41;30mdnscrypt-proxy --local-address=127.0.0.1:53 \ \n --provider-key=$pub \ \n --resolver-address=$IP:5553 \ \n --provider-name=2.dnscrypt-cert.${dnscrypt}.org -d\033[0m"
	echo "#######################################################################"
	echo ""

	read -p "刚刚更新了系统内核和默认shell，是否重启系统 ? (y/n) [默认=n]:" yy
	echo "#######################################################################"

	case $yy in
		y|Y)
			init 6
			;;
		n|N)
			any_key_to_continue
			mainmenu
			;;
		*)
			any_key_to_continue
			mainmenu
			;;
	esac
}

submenu1(){

	echo "#######################################################################"
	echo ""
	echo "(0) 返回"
	echo "(1) 升级系统，升级内核，清理系统"
	echo "(2) 升级系统"
	echo "(3) 升级内核"
	echo "(4) 清理系统"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认5s后自动执行(1)]:"  -t 5 xx1
		if [ -z ${xx1} ] ; then
			xx1=1
		fi

	case $xx1 in
		0)
			mainmenu
			;;
		1)
			updatesystem
			updatekernel
			clearsystem
			rebootcheck
			;;
		2)
			updatesystem
			submenu1
			;;
		3)
			updatekernel
			rebootcheck
			;;
		4)
			clearsystem
			submenu1
			;;
		*)
			updatesystem
			updatekernel
			clearsystem
			rebootcheck
			;;
	esac
}

submenu2(){

	echo "#######################################################################"
	echo ""
	echo "(0) 返回"
	echo "(1) 更换root密码，新增ssh免密码验证用户"
	echo "(2) 更换root密码"
	echo "(3) 新增ssh免密码验证用户"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认5s后自动执行(1)]:"  -t 5 xx2
		if [ -z ${xx2} ] ; then
			xx2=1
		fi

	case $xx1 in
		0)
			mainmenu
			;;
		1)
			changerootpasswd
			add_newuser
			submenu2
			;;
		2)
			changerootpasswd
			submenu2
			;;
		3)
			add_newuser
			submenu2
			;;
		*)
			changerootpasswd
			add_newuser
			submenu2
			;;
	esac
}

mainmenu(){

	clear
	echo "#######################################################################"
	echo ""
	echo "进入正式安装......"
	echo ""
	echo "(0) 退出"
	echo "(1) 默认全部安装"
	echo "(2) 升级系统，升级内核，清理系统"
	echo "(3) 更换root密码，新增ssh免密码验证用户"
	echo "(4) 安装ckrootkit和rkhunter"
	echo "(5) 安装fail2ban"
	echo "(6) 安装lynis"
	echo "(7) 安装zsh"
	echo "(8) 安装shadowsocks"
	echo "(9) 安装l2tp"
	echo "(10) 安装v2ray"
	echo "(11) 安装supervisor"
	echo "(12) 安装vlmcsd"
	echo "(13) 安装kcptun"
	echo "(14) 安装dnscrypt"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认5s后自动执行(1)]:" -t 5 xx
		if [ -z ${xx} ] ; then
			xx=1
		fi

	case $xx in
		0)
			exit
			;;
		1)
			install_all
			mainmenu
			;;
		2)
			submenu1
			;;
		3)
			submenu2
			;;
		4)
			install_ckrootkit_rkhunter
			mainmenu
			;;
		5)
			install_fail2ban
			mainmenu
			;;
		6)
			install_lynis
			mainmenu
			;;
		7)
			install_zsh
			mainmenu
			;;
		8)
			install_shadowsocks
			mainmenu
			;;
		9)
			tunavailable
			install_l2tp
			mainmenu
			;;
		10)
			install_v2ray
			mainmenu
			;;
		11)
			install_supervisor
			mainmenu
			;;
		12)
			install_vlmcsd
			mainmenu
			;;
		13)
			install_kcptun
			mainmenu
			;;
		14)
			install_dnscrypt
			mainmenu
			;;
		*)
			install_all
			mainmenu
			;;
	esac
}

clear
echo "#######################################################################"
echo ""
echo "GO GO GO v0.1.18 ..."
echo ""
echo "#######################################################################"
echo ""
rootness
disable_selinux
set_sysctl
get_os_info
pre_install
mainmenu
