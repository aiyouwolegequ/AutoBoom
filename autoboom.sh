#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

SHELL_VERSION=1.5

rootness(){

	if [ $(id -u) != "0" ]; then
		echo "错误:需要root权限！"
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

	if [ ! -e "/dev/net/tun" ]; then
		echo "错误:这台服务器无法配置VPN！" 1>&2
		any_key_to_continue
		mainmenu
	fi
}

disable_selinux(){

	selinux=`getenforce`

	if [ "$selinux" = "Enforcing" ] ; then
		sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
		setenforce 0
		echo "SElinux已禁用..."
		echo ""
		echo "#######################################################################"
	fi
}

get_opsy(){

	[ -f "/etc/redhat-release" ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
}

get_os_info(){

	local cname=$(awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
	local cores=$(awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo)
	local freq=$(awk -F: '/cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo | sed 's/^[ \t]*//;s/[ \t]*$//')
	local tram=$(free -m | awk '/Mem/ {print $2}')
	local swap=$(free -m | awk '/Swap/ {print $2}')
	local up=$(awk '{a=$1/86400;b=($1%86400)/3600;c=($1%3600)/60;d=$1%60} {printf("%ddays, %d:%d:%d\n",a,b,c,d)}' /proc/uptime)
	local load=$(w | head -1 | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//;s/[ \t]*$//')
	local opsy=$(get_opsy)
	local arch=$(uname -m)
	local lbit=$(getconf LONG_BIT)
	local host=$(hostname )
	local kern=$(uname -r)
	mkdir -p /var/autoboom/log
	touch /var/autoboom/log/os.log
	echo ""
	echo "################ 系统信息 ################" >/var/autoboom/log/os.log
	echo "" >>/var/autoboom/log/os.log
	echo "CPU 型号	: ${cname}" >>/var/autoboom/log/os.log
	echo "CPU 核心数	: ${cores}" >>/var/autoboom/log/os.log
	echo "CPU 频率	: ${freq} MHz" >>/var/autoboom/log/os.log
	echo "内存大小	: ${tram} MB" >>/var/autoboom/log/os.log
	echo "缓存大小	: ${swap} MB" >>/var/autoboom/log/os.log
	echo "开机运行时间	: ${up}" >>/var/autoboom/log/os.log
	echo "平均负载	: ${load}" >>/var/autoboom/log/os.log
	echo "系统		: ${opsy}" >>/var/autoboom/log/os.log
	echo "位数		: ${arch} (${lbit} Bit)" >>/var/autoboom/log/os.log
	echo "内核		: ${kern}" >>/var/autoboom/log/os.log
	echo "主机名		: ${host}" >>/var/autoboom/log/os.log
	echo "IP地址		: ${IP}" >>/var/autoboom/log/os.log
	echo "" >>/var/autoboom/log/os.log
	echo "#########################################" >>/var/autoboom/log/os.log
	cat /var/autoboom/log/os.log
	echo ""
}

command_exists(){

	command -v "$@" >/dev/null 2>&1
}

rebootcheck(){

	read -p "刚刚更新了系统内核，是否重启系统 ? (y/n) [默认=n]:" input
	echo "#######################################################################"
	case $input in
		y|Y)
		init 6
		;;
		*)
		submenu1
		;;
	esac
}

set_sysctl(){

	echo "net.core.default_qdisc = fq" > /etc/sysctl.conf
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

	for each in `ls /proc/sys/net/ipv4/conf/`;
	do
		echo "net.ipv4.conf.${each}.accept_source_route=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.accept_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.send_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.rp_filter=0" >> /etc/sysctl.conf
	done
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

check_port(){

	is_number(){

		expr $1 + 1 >/dev/null 2>&1
	}

	is_port(){

		local port=$1
		is_number "$port" && \
			[ $port -ge 1 ] && [ $port -le 65535 ]
	}

	is_using(){

		port_using=`lsof -nP -itcp:"$listen_port" | wc -l`

		if [ "$port_using" -ne 0 ]; then
			echo "端口已被占用, 请重新输入!"
			listen_port="$d_listen_port"
			continue
		else
			if [ `firewall-cmd --list-ports | grep "$listen_port" |wc -l` -ne 1 ]; then
				firewall-cmd --quiet --permanent --zone=public --add-port=${listen_port}/tcp
				firewall-cmd --quiet --permanent --zone=public --add-port=${listen_port}/udp
				firewall-cmd --reload
			fi
		fi
	}

	local input=
	[ -z "$listen_port" ] && listen_port="$d_listen_port"

	while :
	do
		read -p "(请输入新端口: 默认为${listen_port}): " input
		if [ -n "$input" ]; then
			if is_port "$input"; then
				listen_port="$input"
				is_using
			else
				echo "输入有误, 请输入 1~65535 之间的数字!"
				continue
			fi
		else
			is_using
		fi

		break
	done
}

check_IP(){

	if [ -z "$IP" ]; then
		IP=`ifconfig -a | grep inet | grep -v 127.0.0.1 | grep -v inet6 | awk '{print $2}' | tr -d "addr:" | head -1`
	fi
}

pre_check(){

	if [ -f "/var/autoboom/version.conf" ]; then
		local pre_version=`cat /var/autoboom/version.conf`
		if [ "$pre_version" = "$SHELL_VERSION" ]; then
			set_sysctl 2>&1
		else
			pre_install
		fi
	else
		pre_install
	fi
}

pre_install(){

	clear
	echo "#######################################################################"
	echo ""
	echo "预安装相关软件!请耐心等待!"
	echo ""
	echo "#######################################################################"
	echo ""
	LANG="en_US.UTF-8"

	cat > /etc/profile<<-EOF
	export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export LC_ALL=en_US.UTF-8
	EOF

	source /etc/profile
	hostnamectl set-hostname ${IP}
	yum clean all -q

	if [ ! -f "/etc/yum.conf.bak" ]; then
		cp /etc/yum.conf /etc/yum.conf.bak
		echo "minrate=1" >> /etc/yum.conf
		echo "timeout=300" >> /etc/yum.conf
	fi

	groupinstalled=`yum grouplist | grep -A 1 "Installed Groups" | sed -n 2p | awk '{print $1}'`

	if [ "$groupinstalled" != "Development" ];then
		yum groupinstall "Development Tools" -q -y
	fi

	if [ ! -f "/etc/pki/rpm-gpg/RPM-GPG-KEY-elrepo.org" ];then
		rpm --quiet --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
	fi

	for a in elrepo-release epel-release yum-plugin-fastestmirror yum-utils deltarpm elrepo-kernel
	do
		if [ `rpm -qa | grep $a |wc -l` -ne 1 ];then
			yum install $a -q -y
		fi
	done

	while [ `rpm -qa |grep epel-release | wc -l` -eq 0 ]
	do
		sed -i "s/^#baseurl/baseurl/g" /etc/yum.repos.d/epel.repo
		sed -i "s/^metalink/#metalink/g" /etc/yum.repos.d/epel.repo
		sed -i "s/^#baseurl/baseurl/g" /etc/yum.repos.d/epel-testing.repo
		sed -i "s/^metalink/#metalink/g" /etc/yum.repos.d/epel-testing.repo
	done

	yum makecache -q
	rm -f /var/run/yum.pid

	yum install asciidoc autoconf automake bind-utils bzip2-devel c-ares-devel curl finger gawk gcc gcc-c++ gettext git glibc-static iproute libev-devel libevent-devel libffi-devel libstdc++-static libtool libtool-ltdl-devel lsof m2crypto make mlocate ncurses-devel net-tools openssl-devel pcre-devel policycoreutils-python ppp psmisc python34-devel python-devel python-pip python-setuptools readline-devel ruby ruby-dev rubygems sqlite-devel swig sysstat tar tk-devel tree unzip vim wget xmlto zlib-devel -q -y
	ldconfig
	wget https://bootstrap.pypa.io/get-pip.py
	python get-pip.py
	python3 get-pip.py
	python -m pip install -U pip -q
	python -m pip install -U distribute -q
	python3 -m pip install --upgrade pip -q
	python -m pip install pygments dnspython gevent wafw00f censys selenium BeautifulSoup4 json2html tabulate configparser parse wfuzz feedparser greenlet -q
	python3 -m pip install scrapy docopt twisted lxml parsel w3lib cryptography pyopenssl anubis-netsec plecost json2html tabulate -q
	updatedb
	locate inittab
	rm -rf get-pip.py

	if [ ! -f "/usr/local/lib/libsodium.so" ];then
		wget -q --tries=3 -O libsodium.tar.gz https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
		tar zxvf libsodium.tar.gz
		pushd libsodium-stable
		./configure
		make && make install
		popd
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
		ldconfig
	fi

	if [ ! -d "/usr/include/mbedtls" ];then
		wget -q --tries=3 https://tls.mbed.org/download/mbedtls-2.6.0-gpl.tgz
		tar xvf mbedtls-2.6.0-gpl.tgz
		pushd mbedtls-2.6.0
		make SHARED=1 CFLAGS=-fPIC
		make DESTDIR=/usr install
		popd
		ldconfig
	fi

	if [ ! -f "/usr/local/lib/libevent.so" ];then
		wget -q --tries=3 https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
		tar zxvf libevent-2.1.8-stable.tar.gz
		pushd libevent-2.1.8-stable
		./configure
		make && make install
		popd
		ldconfig
	fi

	rm -rf libsodium* mbedtls* libevent*
	mkdir -p /var/autoboom/
	touch /var/autoboom/version.conf
	echo "$SHELL_VERSION" > /var/autoboom/version.conf
	clear
	echo "#######################################################################"
	echo ""
	echo "预安装完成!"
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
	echo "请耐心等待!"
	cd
	rm -f /var/run/yum.pid
	yum upgrade -q -y
	yum update -q -y
	yum autoremove -q -y
	yum makecache -q
	yum-complete-transaction --cleanup-only -q -y
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm --quiet -Va --nofiles --nodigest
	yum clean all -q -y
	rm -rf /var/cache/yum
	rpm --quiet --rebuilddb
	echo "#######################################################################"
	echo ""
	echo "升级完毕!"
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
	echo "请耐心等待!"

	if [ `rpm -qa | grep kernel-ml |wc -l` -ne 1 ];then
		yum --enablerepo=elrepo-kernel install kernel-ml -q -y
	fi

	egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
	grub2-set-default 0
	modprobe tcp_bbr
	modprobe tcp_htcp
	modprobe tcp_hybla
	echo "tcp_bbr" > /etc/modules-load.d/modules.conf
	echo "#######################################################################"
	echo ""
	echo "升级完毕!"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

changerootpasswd(){

	clear
	echo "#######################################################################"
	echo ""
	read -p "是否需要更换root密码? (y/n) [默认=n]:" input
		case "$input" in
			y|Y)
				newrootpasswd=`randpasswd`
				echo ""
				echo "#######################################################################"
				echo ""
				echo "正在更换root密码!"
				echo ""
				echo "#######################################################################"
				echo "${newrootpasswd}" | passwd --stdin root
				echo "#######################################################################"
				echo ""
				echo -e "新root密码为	:\033[41;30m${newrootpasswd}\033[0m"
				echo "请妥善保存root密码!"
				echo ""
				echo "#######################################################################"
				echo ""
				any_key_to_continue
				;;
			*)
				any_key_to_continue
				;;
		esac
}

add_newuser(){

	clear
	echo "#######################################################################"
	echo ""
	read -p "是否需要新增用户? (y/n) [默认=n]:" input
		case "$input" in
			y|Y)
				newusername=`randusername`
				newuserpasswd=`randpasswd`
				echo ""
				echo "#######################################################################"
				echo ""
				echo "新建一个非root权限的系统用户!"
				echo ""
				echo "#######################################################################"
				useradd -m ${newusername}
				echo "${newuserpasswd}" | passwd --stdin ${newusername}
				echo "#######################################################################"
				echo ""
				echo "请保存好用户名和密码!"
				echo -e "Username:\033[41;30m${newusername}\033[0m"
				echo -e "Password:\033[41;30m${newuserpasswd}\033[0m"
				echo ""
				echo "#######################################################################"
				echo ""
				any_key_to_continue
				echo "#######################################################################"
				echo ""
				read -p "是否需要设置ssh? (y/n) [默认=n]:" input
				case "$input" in
					y|Y)
						add_ssh
						;;
					*)
						any_key_to_continue
						;;
				esac
				;;
			*)
				clear
				echo "#######################################################################"
				echo ""
				read -p "是否需要设置ssh? (y/n) [默认=n]:" input
				case "$input" in
					y|Y)
						echo "#######################################################################"
						echo ""
						echo "现有的普通账户为:"
						getent passwd | grep home | awk -F: '{print $1}'
						while :
						do
							echo ""
							echo "#######################################################################"
							read -p "请输入需要设置ssh的普通账户:" input
							newusername=${input}
							if [ -n "$newusername" ]; then
								if [ `getent passwd | grep "$newusername" | wc -l` -eq 1 ]; then
									add_ssh
								else
									echo "输入有误, 重新请输入!"
									echo ""
									echo "#######################################################################"
									echo ""
									echo "现有的普通账户为:"
									getent passwd | grep home | awk -F: '{print $1}'
									continue
								fi
							fi
							break
						done
						;;
					*)
						any_key_to_continue
						;;
				esac
				;;
		esac
}

add_ssh(){

	setenforce 0

	check_user(){

		if [ -z "$newusername" ]; then
			newusername=`whoami`
			sshdir=/root
		fi
	}

	clear
	local d_listen_port=10010
	local sshdir=/home/${newusername}
	local port=`cat /etc/ssh/sshd_config | grep -w "Port" | awk '{print $2}' | uniq`
	local listen_port=
	read -p "当前ssh端口为${port}，是否需要更换端口? (y/n) [默认=n]:" input
	case "$input" in
		y|Y)
			echo "#######################################################################"
			echo ""
			check_port
			echo "#######################################################################"
			echo ""
			echo "更换ssh端口为${listen_port}，禁用root登陆ssh，禁用密码认证，设置免密钥登陆"
			echo ""
			echo "#######################################################################"
			if [ ! -f "/etc/firewalld/services/ssh.xml" ]; then
				cp /usr/lib/firewalld/services/ssh.xml /etc/firewalld/services/
			fi

			if [ "$port" != "$listen_port" ]; then
				sed -i "s/$port/$listen_port/g" /etc/firewalld/services/ssh.xml
				if [ ! -f "/etc/ssh/sshd_config.bak" ]; then
					cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
					sed -i "s/Port $port/Port $listen_port/g" /etc/ssh/sshd_config
					echo "PermitRootLogin no" >> /etc/ssh/sshd_config
					echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
					echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
					echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
					echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
					echo "Protocol 2" >> /etc/ssh/sshd_config
					echo "Port ${listen_port}" >> /etc/ssh/sshd_config
					sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
				else
					rm -rf /etc/ssh/sshd_config.bak
					cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
					sed -i "s/Port $port/Port $listen_port/g" /etc/ssh/sshd_config
					firewall-cmd --zone=public --remove-port=${port}/tcp --permanent --quiet
					firewall-cmd --zone=public --remove-port=${port}/udp --permanent --quiet
					firewall-cmd --reload
				fi
			fi
			;;
		*)
			listen_port=$port
			any_key_to_continue
			;;
	esac

	while :
	do
		echo "#######################################################################"
		echo ""
		read -p "请输入管理该服务器的电脑的公钥（可以使用cat .ssh/id_rsa.pub查看）:" input
			echo ""
			echo "#######################################################################"
			if [ -z "$input" ]; then
				echo "公钥不能为空!"
				continue
			else
				check_user
				pub=$input

				if [ -f "${sshdir}/.ssh/authorized_keys" ]; then
					su - ${newusername} -c "echo ${pub} >> ${sshdir}/.ssh/authorized_keys"
				else
					su - ${newusername} -c "ssh-keygen -t rsa -P '' -f ${sshdir}/.ssh/id_rsa"
					su - ${newusername} -c "touch ${sshdir}/.ssh/authorized_keys"
					su - ${newusername} -c "chmod 700 ${sshdir}/.ssh"
					su - ${newusername} -c "chmod 644 ${sshdir}/.ssh/authorized_keys"
					su - ${newusername} -c "echo ${pub} >> ${sshdir}/.ssh/authorized_keys"
				fi
		 		break
		 	fi
	done

	systemctl restart sshd
	check_IP
	echo "请使用该命令测试ssh是否正常: ssh -p ${listen_port} ${newusername}@${IP}"
	echo "#######################################################################"
	read -p "请确认ssh是否正常? (y/n) [默认=y]:" input
		echo "#######################################################################"
		case "$input" in
			n|N)
				clear
				echo "#######################################################################"
				echo ""
				echo "恢复为原ssh配置"
				echo ""
				echo "#######################################################################"
				rm -rf /etc/ssh/sshd_config
				mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
				sed -i "s/$listen_port/$port/g" /etc/firewalld/services/ssh.xml
				firewall-cmd --zone=public --remove-port=${listen_port}/tcp --permanent --quiet
				firewall-cmd --zone=public --remove-port=${listen_port}/udp --permanent --quiet
				firewall-cmd --reload
				systemctl restart sshd
				clear
				echo "#######################################################################"
				echo "请使测试ssh是否恢复正常!"
				read -p "如果ssh不正常请Ctrl + C退出脚本手动检查ssh配置,是否恢复正常? (y/n) [默认=y]:" input
				case "$input" in
					n|N)
						exit
						;;
					*)
						clear
						echo "#######################################################################"
						echo "请在脚本完成后手动设置ssh密钥登陆"
						echo "#######################################################################"
						echo ""
						any_key_to_continue
						;;
				esac
				;;
			*)
				echo ""
				any_key_to_continue
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
	cd

	if [ ! -f "/bin/rkhunter" ]; then
		yum install rkhunter -q -y
	fi

	if [ ! -f "/usr/local/bin/chkrootkit" ]; then
		wget -q --tries=3 ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz

		if [ -a "chkrootkit.tar.gz" ]; then
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
			rm -rf chkrootkit*
		fi
	fi

	if [ -e "/usr/local/bin/chkrootkit" -a -e "/bin/rkhunter" ]; then
		rkhunter --update
		rkhunter --propupd
		clear
		echo "#######################################################################"
		echo ""
		echo "正在检测系统，请耐心等待!日志保存在/var/autoboom/log/chkrootkit.log和rkhunter.log"
		echo ""
		echo "#######################################################################"
		echo ""
		rkhunter --check --sk | grep Warning
		chkrootkit > /var/autoboom/log/chkrootkit.log
		cat /var/autoboom/log/chkrootkit.log| grep INFECTED
		mv /var/log/rkhunter/rkhunter.log /var/autoboom/log/
		cd
		echo "#######################################################################"
		echo ""
		echo "ckrootkit和rkhunter安装完毕."
		echo ""
		echo "#######################################################################"
		echo ""
	else
		echo "#######################################################################"
		echo ""
		echo "ckrootkit安装失败，请稍后再试."
		echo ""
		echo "#######################################################################"
		echo ""
	fi

	auto_continue
}

install_aide(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装aide"
	echo ""
	echo "#######################################################################"
	echo ""
	cd

	if [ ! -f "/bin/aide" ]; then
		yum install aide -q -y
		aide --init
		cp -rf /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
	fi

	aide --check
	aide --update
	echo "#######################################################################"
	echo ""
	echo "aide安装完毕."
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

	if [ ! -f "/bin/fail2ban-client" ]; then
		yum install fail2ban fail2ban-firewalld fail2ban-systemd -q -y
		cat > /etc/fail2ban/jail.local<<-EOF
		[DEFAULT]
		banaction = firewallcmd-ipset
		bantime  = 86400
		findtime = 600
		maxretry = 3
		backend = systemd
		ignoreip = 127.0.0.1/8 172.16.18.0/24 202.59.250.200 202.64.170.26 210.92.18.82 210.92.18.73
		EOF

		cat > /etc/fail2ban/jail.d/sshd.local<<-EOF
		[sshd]
		enabled = true
		port = 10010
		logpath  = /var/log/secure
		EOF

		systemctl enable firewalld
		systemctl start firewalld
		systemctl enable fail2ban
		systemctl start fail2ban
		systemctl -a | grep fail2ban
	fi

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
	cd

	if [ ! -f "/usr/local/bin/lynis" ]; then
		git clone -q https://github.com/CISOfy/lynis

		if [ -d "lynis" ]; then
			mv lynis /usr/local/
			ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
		fi
	fi

	if [ -f "/usr/local/bin/lynis" ]; then
		lynis update info
		echo "#######################################################################"
		echo ""
		echo "正在检测系统，请耐心等待!"
		echo ""
		echo "#######################################################################"
		lynis audit system | tee /var/autoboom/log/lynis.log
		echo "#######################################################################"
		echo ""
		echo "lynis安装完成,日志保存在/var/autoboom/log/lynis.log."
		echo ""
		echo "#######################################################################"
		echo ""
	else
		echo "#######################################################################"
		echo ""
		echo "lynis安装失败，请稍后再试."
		echo ""
		echo "#######################################################################"
	fi

	auto_continue
}

install_zsh(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装zsh,请耐心等待!"
	echo ""
	echo "#######################################################################"
	echo ""
	cd

	if [ ! -f "/bin/zsh" ];then
		yum install zsh -q -y
	fi

	if [ -d "/root/.oh-my-zsh" ]; then
		echo "#######################################################################"
		echo ""
		echo "zsh已安装，请使用upgrade_oh_my_zsh升级zsh!"
		echo ""
		echo "#######################################################################"
		echo ""
	else
		umask g-w,o-w
		env git clone -q --depth=1 https://github.com/robbyrussell/oh-my-zsh.git /root/.oh-my-zsh

		if [ -d "/root/.oh-my-zsh" ]; then
			if [ -f ~/.zshrc ] || [ -h ~/.zshrc ]; then
				mv ~/.zshrc ~/.zshrc.pre-oh-my-zsh
			fi

			cp /root/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
			sed "/^export ZSH=/ c\\
			export ZSH=/root/.oh-my-zsh
			" ~/.zshrc > ~/.zshrc-omztemp
			mv -f ~/.zshrc-omztemp ~/.zshrc
			cd /root/.oh-my-zsh/themes
			git clone -q https://github.com/dracula/zsh.git
			mv zsh/dracula.zsh-theme .
			rm -rf zsh
			sed -i 's/robbyrussell/dracula/g' ~/.zshrc
			sed -i 's/plugins=(git)/plugins=(sudo zsh-syntax-highlighting git autojump web-search zsh_reload colored-man-pages zsh-autosuggestions zsh-history-substring-search)/g' ~/.zshrc
			cd /root/.oh-my-zsh/plugins
			git clone -q https://github.com/zsh-users/zsh-syntax-highlighting.git
			git clone -q https://github.com/zsh-users/zsh-autosuggestions.git
			git clone -q https://github.com/zsh-users/zsh-history-substring-search.git

			cat >> /root/.zshrc<<-EOF
			export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
			alias vizsh="vim ~/.zshrc"
			alias sourcezsh="source ~/.zshrc"
			alias cat="pygmentize -g"
			alias py="python"
			alias pip="python -m pip"
			alias py3="python3"
			alias pip3="python3 -m pip"
			EOF

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
		else
			echo "#######################################################################"
			echo ""
			echo "zsh安装失败，请稍后再试."
			echo ""
			echo "#######################################################################"
		fi
	fi

	auto_continue
}

install_shadowsocks(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Shadowsocks，请耐心等待!"
	echo ""
	echo "#######################################################################"
	echo ""
	sspasswd=`randpasswd`
	local listen_port=999
	read -p "默认设置ss端口为${listen_port}，是否需要更换端口? (y/n) [默认=n]:" input
	case "$input" in
		y|Y)
			echo "#######################################################################"
			echo ""
			check_port
			echo "#######################################################################"
			echo ""
			echo "更换默认端口为${listen_port}."
			echo ""
			echo "#######################################################################"
			;;
		*)
			if [ `firewall-cmd --list-ports | grep ${listen_port} |wc -l` -ne 1 ]; then
				firewall-cmd --zone=public --add-port=${listen_port}/tcp --permanent
				firewall-cmd --zone=public --add-port=${listen_port}/udp --permanent
				firewall-cmd --reload
			fi
			;;
	esac

	cd
	git clone -q https://github.com/shadowsocks/shadowsocks-libev.git

	if [ -d "/root/shadowsocks-libev" ]; then
		cd shadowsocks-libev
		git submodule update --init --recursive
		./autogen.sh
		./configure --with-sodium-include=/usr/local/include --with-sodium-lib=/usr/local/lib --with-mbedtls-include=/usr/include --with-mbedtls-lib=/usr/lib
		make && make install
		cd
		rm -rf shadowsocks-libev

		if [ ! -d "/etc/shadowsocks-libev/" ]; then
			mkdir /etc/shadowsocks-libev/
		fi

		cat > /etc/shadowsocks-libev/config.json<<-EOF
		{
			"server":"0.0.0.0",
			"server_port":"${listen_port}",
			"local_port":1080,
			"local_address":"127.0.0.1",
			"password":"${sspasswd}",
			"nameserver": "8.8.8.8",
			"timeout":"600",
			"method":"aes-256-cfb"
		}
		EOF

		cat > /etc/sysconfig/shadowsocks-libev<<-EOF
		START=yes
		CONFFILE="/etc/shadowsocks-libev/config.json"
		DAEMON_ARGS="-u --fast-open --no-delay --mtu 1300 --reuse-port -d 8.8.8.8"
		USER=root
		GROUP=root
		MAXFD=32768
		EOF

		cat > /usr/lib/systemd/system/shadowsocks-libev.service<<-EOF
		[Unit]
		Description=Shadowsocks-libev Default Server Service
		After=network.target

		[Service]
		Type=simple
		PIDFile=/var/run/shadowsocks.pid
		EnvironmentFile=/etc/sysconfig/shadowsocks-libev
		User=root
		Group=root
		LimitNOFILE=32768
		ExecStart=/usr/local/bin/ss-server -a \$USER -c \$CONFFILE \$DAEMON_ARGS

		[Install]
		WantedBy=multi-user.target
		EOF

		cat > /etc/shadowsocks-libev/local.acl<<-EOF
		[white_list]
		127.0.0.1
		::1
		10.0.0.0/8
		172.16.0.0/12
		192.168.0.0/16
		120.41.0.0/16
		EOF

		systemctl daemon-reload
		systemctl start shadowsocks-libev.service
		systemctl enable shadowsocks-libev.service
		systemctl -a | grep shadowsocks
		wget -q --tries=3 https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/shadowsocks_bin.sh
		chmod +x shadowsocks_bin.sh
		./shadowsocks_bin.sh
		rm -rf ./shadowsocks_bin.sh
		echo "#######################################################################"
		echo ""
		echo "Shadowsocks安装完毕."
		echo ""
		echo "#######################################################################"
		echo ""
		echo "Shadowsocks的相关配置:"
		echo -e "Server IP:\033[41;30m${IP}\033[0m"
		echo -e "Port:\033[41;30m${listen_port}\033[0m"
		echo -e "Password:\033[41;30m${sspasswd}\033[0m"
		echo -e "Encryption:\033[41;30maes-256-cfb\033[0m"
		echo ""
		echo "#######################################################################"
		echo ""
	else
		echo "#######################################################################"
		echo ""
		echo "Shadowsocks安装失败，请稍后再试."
		echo ""
		echo "#######################################################################"
	fi

	any_key_to_continue
}

install_pptp(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始配置PPTP VPN:"
	echo ""
	echo "#######################################################################"
	pptpuser=`randusername`
	pptppasswd=`randpasswd`
	yum install pptpd -q -y
	cp /etc/pptpd.conf /etc/pptpd.conf.bak

	cat > /etc/pptpd.conf<<-EOF
	option /etc/ppp/options.pptpd
	#logwtmp
	localip 10.0.10.1
	remoteip 10.0.10.2-254
	listen $IP
	EOF

	cp /etc/ppp/options.pptpd /etc/ppp/options.pptpd.bak

	cat > /etc/ppp/options.pptpd<<-EOF
	name pptpd
	refuse-pap
	refuse-chap
	refuse-mschap
	require-mschap-v2
	require-mppe-128
	proxyarp
	lock
	nobsdcomp
	novj
	novjccomp
	nologfd
	ms-dns 8.8.8.8
	ms-dns 8.8.4.4
	EOF

	echo "${pptpuser} pptpd ${pptppasswd} *" >> /etc/ppp/chap-secrets

	cat > /etc/firewalld/services/pptp.xml<<-EOF
	<?xml version="1.0" encoding="utf-8"?>
	<service>
	  <port protocol="tcp" port="1723"/>
	</service>
	EOF

	firewall-cmd --quiet --permanent --zone=public --add-service=pptp
	local str=`firewall-cmd --list-all | grep masquerade | awk '{print $2}'`

	if [ "${str}" != "yes" ]; then
		firewall-cmd --quiet --permanent --zone=public --add-masquerade
	fi

	firewall-cmd --reload
	modprobe ip_nat_pptp
	systemctl start pptpd.service
	systemctl enable pptpd.service
	systemctl -a | grep pptpd
	echo "#######################################################################"
	echo ""
	echo "PPTP VPN安装完毕."
	echo ""
	echo "#######################################################################"
	echo "PPTP VPN的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "Username:\033[41;30m${pptpuser}\033[0m"
	echo -e "Password:\033[41;30m${pptppasswd}\033[0m"
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_l2tp(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始配置L2TP VPN:"
	echo ""
	echo "#######################################################################"
	echo ""
	username=`randusername`
	password=`randpasswd`
	mypsk=`randpsk`
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

	any_key_to_continue
	yum install libreswan xl2tpd -q -y
	sysctl -p
	systemctl start ipsec
	systemctl start xl2tpd
	systemctl enable ipsec
	systemctl enable xl2tpd
	systemctl -a | grep ipsec
	systemctl -a | grep xl2tpd

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

	echo "${username} l2tpd ${password} *" >> /etc/ppp/chap-secrets
	firewall-cmd --quiet --permanent --add-service=ipsec
	firewall-cmd --quiet --permanent --add-service=xl2tpd
	local str=`firewall-cmd --list-all | grep masquerade | awk '{print $2}'`

	if [ "${str}" != "yes" ]; then
		firewall-cmd --quiet --permanent --zone=public --add-masquerade
	fi

	firewall-cmd --reload
	systemctl restart ipsec
	systemctl restart xl2tpd
	systemctl -a | grep ipsec
	systemctl -a | grep xl2tpd
	cd
	wget -q --tries=3 https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/l2tp_bin.sh
	chmod +x l2tp_bin.sh
	./l2tp_bin.sh
	rm -rf l2tp_bin.sh
	sleep 3
	ipsec verify
	echo ""
	echo "如果没有出现FAILED，说明L2TP VPN安装完毕，请测试使用是否正常."
	echo ""
	echo "#######################################################################"
	echo "L2TP VPN的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "PSK:\033[41;30m${mypsk}\033[0m"
	echo -e "Username:\033[41;30m${username}\033[0m"
	echo -e "Password:\033[41;30m${password}\033[0m"
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

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装v2ray，请耐心等待!"
	echo ""
	echo "#######################################################################"
	echo ""
	local d_listen_port=8888
	local v2ray_status=0
	local ver=`curl -s https://api.github.com/repos/v2ray/v2ray-core/releases/latest --connect-timeout 10| grep 'tag_name' | cut -d\" -f4`
	local UUID=$(cat /proc/sys/kernel/random/uuid)
	rm -rf /tmp/v2ray
	mkdir -p /tmp/v2ray
	curl -s -L -H "Cache-Control: no-cache" -o /tmp/v2ray/v2ray.zip https://github.com/v2ray/v2ray-core/releases/download/${ver}/v2ray-linux-64.zip

	if [ -f "/tmp/v2ray/v2ray.zip" ]; then
		unzip -qo /tmp/v2ray/v2ray.zip -d /tmp/v2ray/
		rm -rf /usr/bin/v2ray /etc/v2ray/ /var/log/v2ray
		mkdir -p /usr/bin/v2ray /etc/v2ray /var/log/v2ray
		cd /tmp/v2ray/v2ray-${ver}-linux-64/
		mv -f geoip.dat geosite.dat v2ray v2ctl /usr/bin/v2ray/
		chmod +x /usr/bin/v2ray/v2ray /usr/bin/v2ray/v2ctl
		mv -f "/tmp/v2ray/v2ray-${ver}-linux-64/vpoint_vmess_freedom.json" "/etc/v2ray/config.json"
		read -p "默认设置vmess端口为${d_listen_port}，是否需要更换端口? (y/n) [默认=n]:" input
		case "$input" in
			y|Y)
				echo "#######################################################################"
				echo ""
				check_port
				echo "#######################################################################"
				echo ""
				echo "更换默认vmess端口为${listen_port}."
				echo ""
				echo "#######################################################################"
				d_listen_port="$listen_port"
				;;
			*)
				;;
		esac

		sed -i "s/10086/${d_listen_port}/g" "/etc/v2ray/config.json"
		sed -i "s/23ad6b10-8d1a-40f7-8ad0-e3e35cd38297/${UUID}/g" "/etc/v2ray/config.json"
		mv -f "/tmp/v2ray/v2ray-${ver}-linux-64/systemd/v2ray.service" "/usr/lib/systemd/system/"
		systemctl daemon-reload
		systemctl enable v2ray.service
		systemctl start v2ray
		rm -rf /tmp/v2ray
		systemctl -a | grep v2ray
		echo "#######################################################################"
		echo ""
		echo "V2Ray安装完毕."
		echo ""
		echo "V2Ray的相关配置:"
		echo -e "Server IP:\033[41;30m${IP}\033[0m"
		echo -e "UUID:\033[41;30m${UUID}\033[0m"
		echo -e "V2Ray Port:\033[41;30m${d_listen_port}\033[0m"
		echo "#######################################################################"
		echo ""
	else
		echo "#######################################################################"
		echo ""
		echo "V2Ray安装失败，请稍后再试."
		echo ""
		echo "#######################################################################"
	fi

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
			set -x
			echo "${verify}  ${file}" | $verify_cmd -c
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

			any_key_to_continue
			mainmenu
		fi

		set -x; wget -q  --tries=3 -O "$file" --no-check-certificate "$url"

		if [ "$?" != "0" ] || [ -n "$verify_cmd" ] && ! verify_file; then
			retry=$(expr $retry + 1)
			download_file_to_path
		fi
	}

	config_install_supervisor(){

		if [ ! -d "/etc/supervisor/conf.d" ]; then
			set -x
			mkdir -p /etc/supervisor/conf.d
		fi

		if [ ! -f "/usr/local/bin/supervisord" ]; then
			set -x
			ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/supervisorctl" ]; then
			set -x
			ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/pidproxy" ]; then
			set -x
			ln -s "$(command -v pidproxy)" '/usr/local/bin/pidproxy' 2>/dev/null
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

			set -x
			echo_supervisord_conf >"$cfg_file" 2>/dev/null


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
			supervisor_startup_file_url="https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/supervisord.systemd"
			download_file "$supervisor_startup_file_url" "$supervisor_startup_file"
			set -x
			systemctl daemon-reload >/dev/null 2>&1
		fi
	}

	if [ -z "/etc/supervisord.conf" ] && command_exists supervisord; then

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

	if [ -n "/etc/supervisor/supervisord.conf" ]; then
		easy_install -U supervisor
		config_install_supervisor
		download_startup_file
	fi

	if command_exists supervisord; then
		systemctl start supervisord.service
		supervisorctl update
		supervisorctl reread
		supervisorctl status
		echo "#######################################################################"
		echo ""
		echo "Supervisor安装完毕."
		echo ""
		echo "#######################################################################"
		echo ""
	else
		echo "#######################################################################"
		echo ""
		echo "Supervisor安装失败，请稍后再试.."
		echo ""
		echo "#######################################################################"
		echo ""
	fi

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

	if [ `firewall-cmd --list-ports | grep 1688 | wc -l` -ne 1 ]; then
		firewall-cmd --zone=public --add-port=1688/tcp --permanent
		firewall-cmd --zone=public --add-port=1688/udp --permanent
		firewall-cmd --reload
	fi

	if [ -s "/etc/init.d/vlmcsd" ]; then
		/etc/init.d/vlmcsd stop
		/sbin/chkconfig --del vlmcsd
		rm -f /etc/init.d/vlmcsd
	fi

	if [ -s "/usr/local/bin/vlmcsdmulti-x64-musl-static" ]; then
		rm -f /usr/local/bin/vlmcsdmulti-x64-musl-static
	fi

	wget -q --tries=3 -O /usr/local/bin/vlmcsd --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/vlmcsd.server
	chmod 0755 /usr/local/bin/vlmcsd
	wget -q --tries=3 -O /usr/local/bin/vlmcsdmulti-x64-musl-static --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/vlmcsdmulti-x64-musl-static
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
	systemctl -a | grep vlmcsd
	echo "#######################################################################"
	echo ""
	echo "Vlmcsd安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_kcptun(){

	local install_dir='/usr/local/kcptun'
	local log_dir='/var/log/kcptun'
	local jq_bin="${install_dir}/bin/jq"
	local d_key=`randpasswd`
	local current_instance_id=
	local run_user='kcptun'
	local target_addr=${IP}
	local listen_port=800
	local target_port=999

	set_snmp(){

		snmplog="$(get_current_file 'snmp')"
		local input=
		[ -z "$snmpperiod" ] && snmpperiod="60"
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

		echo "${install_dir}/server_$file_suffix"
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
					client_config="$(echo "$client_config" | $jq_bin -r ".${k}=${v}")"
				else
					client_config="$(echo "$client_config" | $jq_bin -r ".${k}=\"${v}\"")"
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

		wget -q --tries=3 https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/kcptun_bin.sh
		chmod +x kcptun_bin.sh
		./kcptun_bin.sh
		rm -rf kcptun_bin.sh
		local server_ip=
		server_ip="${IP}"
		clear
		echo ""
		echo "Kcptun的相关配置:"
		echo ""
		echo "#######################################################################"
		echo ""
		printf "ip:\033[41;30m ${server_ip} \033[0m\n"
		printf "port:\033[41;30m ${listen_port} \033[0m\n"
		printf "address:\033[41;30m ${target_addr}:${target_port}\033[0m\n"
		show_configs "key" "crypt" "mode" "mtu" "sndwnd" "rcvwnd" "datashard" \
			"parityshard" "dscp" "nocomp" "nodelay" "interval" "resend" \
			"nc" "acknodelay" "sockbuf" "keepalive"
		show_version_and_client_url
		install_jq
		local client_config=

		read -d '' client_config <<-EOF
		{
		  "localaddr"	: ":${target_port}",
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
		[ -z "$nodelay" ] && nodelay="1"

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

		[ -z "$interval" ] && interval="20"
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

		[ -z "$resend" ] && resend="2"
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

		[ -z "$nc" ] && nc="1"
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

			( set -x; wget -q --tries=3 -O "$file" --no-check-certificate "$url" )

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

		if [ ! -f "$jq_bin" ]; then
			return 1
		fi

		[ ! -x "$jq_bin" ] && chmod a+x "$jq_bin"

		if ( $jq_bin --help 2>/dev/null | grep -q "JSON" ); then
			is_checkd_jq="true"
			return 0
		else
			rm -f "$jq_bin"
			return 1
		fi
	}

	install_jq(){

		if [ -z "$is_checkd_jq" ] && ! check_jq; then
			local dir=
			dir="$(dirname "$jq_bin")"

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
					download_file "https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/jq-linux64" "$jq_bin" "d8e36831c3c94bb58be34dd544f44a6c6cb88568"
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

			if port_using "$listen_port" ; then
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

		[ -z "$target_addr" ] && target_addr="$target_addr"

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

		[ -z "$target_port" ] && target_port="999"
		while :
		do
			cat >&1 <<-EOF
			请输入需要加速的SS端口 [1~65535]
			EOF

			read -p "(默认SS端口为: ${target_port}): " input
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
				read -p "当前没有软件使用此端口, 确定加速此端口? [y/n]: " input
				if [ -n "$input" ]; then
					case "${input:0:1}" in
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

		[ -z "$key" ] && key="$d_key"

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

		[ -z "$crypt" ] && crypt="salsa20"
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

		[ -z "$mode" ] && mode="fast3"
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

		[ -z "$mtu" ] && mtu="1300"

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

		[ -z "$sndwnd" ] && sndwnd="2048"

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

		[ -z "$rcvwnd" ] && rcvwnd="2048"

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

		[ -z "$datashard" ] && datashard="10"

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

		[ -z "$parityshard" ] && parityshard="3"

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

		[ -z "$dscp" ] && dscp="0"

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

		[ -z "$nocomp" ] && nocomp="false"

		while :
		do
			cat >&1 <<-EOF
			是否关闭数据压缩?
			EOF

			read -p "(默认: ${nocomp}) [y/n]: " input
			if [ -n "$input" ]; then
				case "${input:0:1}" in
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

		read -p "(默认: 否) [y/n]: " input
		if [ -n "$input" ]; then
			case "${input:0:1}" in
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

		[ -z "$pprof" ] && pprof="false"

		while :
		do
			cat >&1 <<-EOF
			是否开启 pprof 性能监控?
			地址: http://IP:6060/debug/pprof/
			EOF

			read -p "(默认: ${pprof}) [y/n]: " input
			if [ -n "$input" ]; then
				case "${input:0:1}" in
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

		read -p "(默认: 否) [y/n]: " input
		if [ -n "$input" ]; then
			case "${input:0:1}" in
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
			set -x; sleep 3; yum -q -y install ca-certificates
		fi

		if ! command_exists awk; then
			set -x; sleep 3; yum -q -y install gawk
		fi

		if ! command_exists tar; then
			set -x; sleep 3; yum -q -y install tar
		fi

		install_jq
	}

	get_kcptun_version_info(){

		local request_version=$1
		local version_content=

		if [ -n "$request_version" ]; then
			local json_content=
			json_content="$(get_content "https://api.github.com/repos/xtaci/kcptun/releases")"
			version_content="$(get_json_string "$json_content" ".[] | select(.tag_name == \"${request_version}\")")"
		else
			version_content="$(get_content "https://api.github.com/repos/xtaci/kcptun/releases/latest")"
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

		if [ ! -d "$install_dir" ]; then
			set -x
			mkdir -p "$install_dir"
		fi

		if [ ! -d "$log_dir" ]; then
			set -x
			mkdir -p "$log_dir"
			chmod a+w "$log_dir"
		fi

		set -x
		tar -zxf "$kcptun_file_name" -C "$install_dir"
		sleep 3
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

		rm -f "$kcptun_file_name" "${install_dir}/client_$file_suffix"
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

		content="$(wget -q --tries=3 -qO- --no-check-certificate "$url")"

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
				printf '%s/server-config%s.json' "$install_dir" "$current_instance_id"
				;;
			log)
				printf '%s/server%s.log' "$log_dir" "$current_instance_id"
				;;
			snmp)
				printf '%s/snmplog%s.log' "$log_dir" "$current_instance_id"
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
			str="$(echo "$content" | $jq_bin -r "$selector" 2>/dev/null)"

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

		if [ ! -d "/etc/supervisor/conf.d" ]; then
			set -x
			mkdir -p /etc/supervisor/conf.d
		fi

		if [ ! -f "/usr/local/bin/supervisord" ]; then
			set -x
			ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/supervisorctl" ]; then
			set -x
			ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/pidproxy" ]; then
			set -x
			ln -s "$(command -v pidproxy)" '/usr/local/bin/pidproxy' 2>/dev/null
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

			set -x
			echo_supervisord_conf >"$cfg_file" 2>/dev/null

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
			set -x
			mkdir -p "$dir"
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
					json="$(echo "$json" | $jq_bin ".$k=$v")"
				else
					json="$(echo "$json" | $jq_bin ".$k=\"$v\"")"
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

		if ( echo "$target_addr" | grep -q ":" ); then
			target_addr="[${target_addr}]"
		fi

		cat > "$config_file"<<-EOF
		{
		  "listen": ":${listen_port}",
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
		directory=${install_dir}
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

				if ! firewall-cmd --quiet --zone=public --query-port=${listen_port}/udp; then
					firewall-cmd --quiet --permanent --zone=public --add-port=${listen_port}/udp
					firewall-cmd --reload
				fi
			fi
		fi
	}

	start_supervisor(){

		set -x; sleep 3

		if command_exists systemctl; then
			if systemctl status supervisord.service >/dev/null 2>&1; then
				systemctl restart supervisord.service
			else
				systemctl start supervisord.service
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
	echo "开始安装Kcptun,请耐心等待!"
	echo ""
	echo "#######################################################################"
	echo ""
	set_kcptun_config
	install_deps
	kcptun_install

	if [ ! -e "/usr/lib/systemd/system/supervisord.service" ]; then
		install_supervisor
	fi

	gen_kcptun_config
	set_firewall
	start_supervisor
	enable_supervisor
	show_current_instance_info > /var/autoboom/log/kcptun.log
	clear
	echo "#######################################################################"
	echo "请保存好Kcptun配置!"
	echo ""
	sed -n '6,18p' /var/autoboom/log/kcptun.log
	echo "#######################################################################"
	echo ""
	echo "Kcptun安装完毕,日志保存在/var/autoboom/log/kcptun.log."
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
	cd
	git clone -q --recursive git://github.com/cofyc/dnscrypt-wrapper.git
	cd dnscrypt-wrapper
	make configure
	./configure
	make install
	ldconfig
	sleep 1
	cd
	wget -q --tries=3 -O dnscrypt-proxy.tar.gz https://download.dnscrypt.org/dnscrypt-proxy/LATEST.tar.gz
	tar zxvf dnscrypt-proxy.tar.gz
	cd dnscrypt-proxy*
	./configure
	make && make install
	sleep 1
	cd
	rm -rf dnscrypt*
	mkdir ~/.dns
	cd ~/.dns
	dnscrypt-wrapper --gen-provider-keypair > /var/autoboom/log/dns.log
	pub=$(cat /var/autoboom/log/dns.log | grep provider-key | awk '{print $3}' | cut -d "=" -f 2)
	dnscrypt-wrapper --gen-crypt-keypair --crypt-secretkey-file=1.key
	dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=1.key --provider-cert-file=1.cert --provider-publickey-file=public.key --provider-secretkey-file=secret.key --cert-file-expire-days=365
	firewall-cmd --quiet --permanent --zone=public --add-port=5453/tcp
	firewall-cmd --quiet --permanent --zone=public --add-port=5354/tcp
	firewall-cmd --quiet --permanent --zone=public --add-port=3535/tcp
	firewall-cmd --quiet --permanent --zone=public --add-port=5453/udp
	firewall-cmd --quiet --permanent --zone=public --add-port=5354/udp
	firewall-cmd --quiet --permanent --zone=public --add-port=3535/udp
	firewall-cmd --quiet --permanent --zone=public --add-port=53/udp
	firewall-cmd --reload

	if [ ! -e "/usr/lib/systemd/system/supervisord.service" ]; then
		install_supervisor
	fi

	clear

	cat > /etc/supervisor/conf.d/dnscrypt.conf<<-EOF
	[program:dnscrypt-proxy]
	command = /usr/local/sbin/dnscrypt-proxy --local-address=127.0.0.1:5354 --resolver-address=178.216.201.222:2053 --provider-name=2.dnscrypt-cert.soltysiak.com --provider-key=25C4:E188:2915:4697:8F9C:2BBD:B6A7:AFA4:01ED:A051:0508:5D53:03E7:1928:C066:8F21
	startsecs = 5
	autostart = true
	startretries = 3
	user = nobody
	EOF

	systemctl restart supervisord.service
	supervisorctl update
	supervisorctl reread
	supervisorctl status

	cat > /usr/lib/systemd/system/dnscrypt-wrapper.service<<-EOF
	[Unit]
	Description=DNSCrypt Server
	After=network.target
	Wants=network.target

	[Install]
	WantedBy=multi-user.target

	[Service]
	Type=simple
	PIDFile=/var/run/dnscrypt-wrapper.pid
	ExecStart=/usr/local/sbin/dnscrypt-wrapper --listen-address=0.0.0.0:5453 \
	--resolver-address=8.8.8.8:53 \
	--provider-name=2.dnscrypt-cert.${dnscrypt}.org \
	--crypt-secretkey-file=/root/.dns/1.key \
	--provider-cert-file=/root/.dns/1.cert
	Restart=on-failure
	EOF

	systemctl daemon-reload
	systemctl start dnscrypt-wrapper
	systemctl enable dnscrypt-wrapper
	systemctl -a | grep dnscrypt-wrapper
	yum install dnsmasq -q -y
	wget -q --tries=3 http://members.home.nl/p.a.rombouts/pdnsd/releases/pdnsd-1.2.9a-par_sl6.x86_64.rpm
	yum localinstall pdnsd-1.2.9a-par_sl6.x86_64.rpm -q -y
	rm -rf pdnsd-1.2.9a-par_sl6.x86_64.rpm
	cp /etc/pdnsd.conf.sample /etc/pdnsd.conf

	cat > /etc/pdnsd.conf<<-EOF
	global {
	perm_cache=10240;
	cache_dir="/var/cache/pdnsd";
	run_as="pdnsd";
	server_ip = any;
	server_port=3535;
	status_ctl = on;
	# paranoid=on;
	# but may make pdnsd less efficient, unfortunately.
	query_method=tcp_only;
	min_ttl=1d;
	max_ttl=1w;
	timeout=10;
	randomize_recs = on;
	neg_domain_pol=on;
	udpbufsize=1024;
	}

	server {
	label= "googledns";
	ip = 127.0.0.1;
	port = 5354;
	timeout=4;
	uptest=none;
	purge_cache=off;
	edns_query=no;
	exclude = .localdomain;
	}

	source {
	owner=localhost;
	file="/etc/hosts";
	}

	rr {
	name=localhost;
	reverse=on;
	a=127.0.0.1;
	owner=localhost;
	soa=localhost,root.localhost,42,86400,900,86400,86400;
	}
	EOF

	chmod 755 /etc/pdnsd.conf
	systemctl start pdnsd
	systemctl enable pdnsd
	systemctl start dnsmasq.service
	systemctl enable dnsmasq.service
	systemctl -a | grep pdnsd
	systemctl -a | grep dnsmasq

	cat > /etc/dnsmasq.conf<<-EOF
	no-resolv
	no-poll
	server=127.0.0.1#3535
	conf-dir=/etc/dnsmasq.d
	log-queries
	log-facility=/var/log/dnsmasq.log
	EOF

	cat > /etc/resolv.conf<<-EOF
	nameserver 127.0.0.1
	EOF

	supervisorctl restart dnscrypt-proxy
	systemctl restart pdnsd
	systemctl restart dnsmasq
	echo "#######################################################################"
	echo "如需使用dnscrypt可在电脑上使用以下命令:"
	echo -e "\033[41;30mdnscrypt-proxy --local-address=127.0.0.1:53 \ \n --provider-key=$pub \ \n --resolver-address=$IP:5453 \ \n --provider-name=2.dnscrypt-cert.${dnscrypt}.org -d\033[0m" |tee /var/autoboom/log/dnscrypt.log
	echo "或者直接设置${IP}为DNS地址"
	echo "#######################################################################"
	echo ""
	echo "Dnscrypt安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_pentest_tools(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装渗透工具"
	echo ""
	echo "#######################################################################"
	easy_install shodan
	git clone -q https://github.com/lijiejie/subDomainsBrute.git /usr/src/pentest/subDomainsBrute
	git clone -q https://github.com/urbanadventurer/WhatWeb.git /usr/src/pentest/WhatWeb
	git clone -q https://github.com/gelim/censys.git /usr/src/pentest/censys
	git clone -q https://github.com/Xyntax/FileSensor /usr/src/pentest/FileSensor
	git clone -q https://github.com/Xyntax/BingC.git /usr/src/pentest/BingC
	git clone -q https://github.com/TheRook/subbrute.git /usr/src/pentest/subbrute
	git clone -q https://github.com/n4xh4ck5/N4xD0rk.git /usr/src/pentest/N4xD0rk
	git clone -q https://github.com/TheRook/subbrute.git /usr/src/pentest/subbrute
	git clone -q https://github.com/n4xh4ck5/N4xD0rk.git /usr/src/pentest/N4xD0rk
	git clone -q https://github.com/maurosoria/dirsearch.git /usr/src/pentest/dirsearch
	git clone -q https://github.com/stanislav-web/OpenDoor.git /usr/src/pentest/OpenDoor
	git clone -q https://github.com/ekultek/whatwaf.git /usr/src/pentest/whatwaf
	git clone -q https://github.com/aboul3la/Sublist3r.git /usr/src/pentest/Sublist3r
	git clone -q https://github.com/laramies/theHarvester.git /usr/src/pentest/theHarvester
	git clone -q https://github.com/appsecco/bugcrowd-levelup-subdomain-enumeration.git /usr/src/pentest/bugcrowd
	git clone -q https://github.com/darkoperator/dnsrecon /usr/src/pentest/dnsrecon
	git clone -q --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev /usr/src/pentest/sqlmap-dev

	if [ -e "/root/.zshrc" ];then

		cat >> /root/.zshrc<<-EOF
		alias theharvester="python /usr/src/pentest/theHarvester/theHarvester.py -b all -l 1000 -h -d"
		alias subDomainsBrute="python /usr/src/pentest/subDomainsBrute/subDomainsBrute.py"
		alias censys="python /usr/src/pentest/censys/censys_io.py"
		alias censys="python /usr/src/pentest/censys/censys_io.py"
		alias filesensor="python3 /usr/src/pentest/FileSensor/filesensor.py"
		alias bingc="python /usr/src/pentest/BingC/bingC.py"
		alias reverseip="python /usr/src/pentest/ReverseIP/reverseip.py"
		alias sqlmap="python /usr/src/pentest/sqlmap-dev/sqlmap.py"
		alias cdnfinder="docker run -it turbobytes/cdnfinder cdnfindercli --phantomjsbin="/bin/phantomjs" --host"
		alias subdns="python /usr/src/pentest/subbrute/subbrute.py -p"
		alias sublist3r="python /usr/src/pentest/Sublist3r/sublist3r.py -v -d"
		alias n4xd0rk="python /usr/src/pentest/N4xD0rk/n4xd0rk.py -n 100 -t"
		alias anubis="anubis -t -ip --with-nmap -r -d"
		alias whatweb="ruby /usr/src/pentest/WhatWeb/whatweb -v"
		alias dirsearch="python3  /usr/src/pentest/dirsearch/dirsearch.py -u"
		alias wafw00f="wafw00f -r -a -v"
		alias theharvester="python /usr/src/pentest/theHarvester/theHarvester.py"
		alias dnsrecon="python3 /usr/src/pentest/dnsrecon/dnsrecon.py -D /usr/src/pentest/dnsrecon/subdomains-top1mil-20000.txt -t brt"
		EOF

		source /root/.zshrc
	fi

	echo "#######################################################################"
	echo ""
	echo "安装完毕!工具路径为/usr/src/pentest/"
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

	if [ -f ./autoboom.sh ]; then
		rm -rf ./autoboom.sh
	fi

	yum autoremove -q -y
	yum makecache -q
	yum-complete-transaction --cleanup-only -q -y
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm --quiet -Va --nofiles --nodigest
	yum clean all -q -y
	rm -rf /var/cache/yum
	rpm --quiet --rebuilddb
	echo "#######################################################################"
	echo ""
	echo "清理完毕!"
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

usage() {

	cat >&1 <<-EOF
	Usage: autoboom [option]

	[option]: (-l,list|-u,update|-r,remove|-h,help|-v,version)

	-l,list			列出所有项目
	-u,update		升级到最新
	-r,remove		卸载
	-h,help			救命啊
	-v,version		显示当前版本
	EOF

	exit $1
}

install(){

	pre_check 2>&1
	mainmenu
}

update(){

	echo Check for update...
	wget -q --tries=3 --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/autoboom.sh
	chmod +x autoboom.sh
	version=`grep SHELL_VERSION -m1 autoboom.sh | awk -F = '{print $2}'`

	if [ -f "/var/autoboom/version.conf" ]; then
		local pre_version=`cat /var/autoboom/version.conf`
		if [ "$pre_version" = "$version" ]; then
			echo "no update is available - -#"
		else
			if [ -f "/usr/local/bin/autoboom" ]; then
				rm -rf /usr/local/bin/autoboom
			fi

			mv -f autoboom.sh /usr/local/bin/autoboom
			echo "update success ^_^"
			echo $version > /var/autoboom/version.conf
			rm -rf ./autoboom.sh
		fi
	else
		rm -rf ./autoboom.sh
		install
	fi
}

remove(){

	rm -rf /usr/local/bin/autoboom /var/autoboom/version.conf
}

version(){

	echo AutoBoom v$SHELL_VERSION
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
	install_pptp
	install_v2ray
	install_supervisor
	install_vlmcsd
	install_kcptun
	install_dnscrypt
	install_aide
	install_pentest_tools
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
	echo -e "新用户名:\033[41;30m${newusername}\033[0m"
	echo -e "新用户密码:\033[41;30m${newuserpasswd}\033[0m"
	echo -e "root密码:\033[41;30m${newrootpasswd}\033[0m"
	echo ""
	echo "Shadowsocks的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "Port:\033[41;30m999\033[0m"
	echo -e "Password:\033[41;30m${sspasswd}\033[0m"
	echo -e "Encryption:\033[41;30mchacha20-ietf-poly1305\033[0m"
	echo ""
	echo "PPTP VPN的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "Username:\033[41;30m${pptpuser}\033[0m"
	echo -e "Password:\033[41;30m${pptppasswd}\033[0m"
	echo ""
	echo "L2TP VPN的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "PSK:\033[41;30m${mypsk}\033[0m"
	echo -e "Username:\033[41;30m${username}\033[0m"
	echo -e "Password:\033[41;30m${password}\033[0m"
	echo ""
	echo "使用以下命令配置l2tp用户:"
	echo -e "\033[41;30ml2tp -a\033[0m (新建用户)"
	echo -e "\033[41;30ml2tp -d\033[0m (删除用户)"
	echo -e "\033[41;30ml2tp -l\033[0m (列出用户)"
	echo -e "\033[41;30ml2tp -m\033[0m (修改指定用户的密码)"
	echo ""
	echo "V2Ray的相关配置:"
	echo -e "Server IP:\033[41;30m${IP}\033[0m"
	echo -e "UUID:\033[41;30m${UUID}\033[0m"
	echo -e "V2Ray Port:\033[41;30m8888\033[0m"
	echo ""
	echo "如需使用dnscrypt可在电脑上使用以下命令:"
	echo -e "\033[41;30mdnscrypt-proxy --local-address=127.0.0.1:53 \ \n --provider-key=$pub \ \n --resolver-address=$IP:5453 \ \n --provider-name=2.dnscrypt-cert.${dnscrypt}.org -d\033[0m"
	echo "#######################################################################"
	echo ""

	read -p "刚刚更新了系统内核和默认shell，是否重启系统 ? (y/n) [默认=n]:" input
	echo "#######################################################################"

	case $input in
		y|Y)
			init 6
			;;
		*)
			any_key_to_continue
			mainmenu
			;;
	esac
}

submenu1(){

	clear
	echo "#######################################################################"
	echo ""
	echo "(0) 返回"
	echo "(1) 升级系统，升级内核，清理系统"
	echo "(2) 升级系统"
	echo "(3) 升级内核"
	echo "(4) 清理系统"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认执行(1)]:" input
		if [ -z ${input} ] ; then
			input=1
		fi

	case $input in
		0)
			mainmenu
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

	clear
	echo "#######################################################################"
	echo ""
	echo "(0) 返回"
	echo "(1) 更换root密码，新增ssh免密码验证用户"
	echo "(2) 更换root密码"
	echo "(3) 新增ssh免密码验证用户"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认执行(1)]:" input
		if [ -z ${input} ] ; then
			input=1
		fi

	case $input in
		0)
			mainmenu
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
	echo "(15) 安装pptp"
	echo "(16) 安装aide"
	echo "(17) 安装pentest tools"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认执行(1)]:" input
		if [ -z ${input} ] ; then
			input=1
		fi

	case $input in
		0)
			exit
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
		15)
			tunavailable
			install_pptp
			mainmenu
			;;
		16)
			install_aide
			mainmenu
			;;
		17)
			install_pentest_tools
			mainmenu
			;;
		*)
			install_all
			mainmenu
			;;
	esac
}

main(){

	clear
	echo "#######################################################################"
	echo ""
	echo "CentOS 7 服务器一键部署脚本"
	echo "autoboom v$SHELL_VERSION"
	echo "Github: https://github.com/aiyouwolegequ/AutoBoom"
	echo ""
	echo "#######################################################################"
	get_os_info
	disable_selinux
	echo "#######################################################################"
	echo ""
	echo "(0) 退出"
	echo "(1) 部署"
	echo "(2) 更新"
	echo "(3) 卸载"
	echo ""
	echo "#######################################################################"

	read -p "请选择要执行的模块？[默认执行(1)]:" input
		if [ -z ${input} ] ; then
			input=1
		fi

	case $input in
		0)
			exit
			;;
		2)
			update
			;;
		3)
			remove
			;;
		1|*)
			install
			;;
	esac
}

rootness
IP=$(curl -s ipinfo.io | sed -n 2p | awk -F \" '{print $4}')

if [ ! -f "/usr/local/bin/autoboom" ]; then
	mv -f autoboom.sh /usr/local/bin/autoboom
	chmod +x /usr/local/bin/autoboom
fi

action=${1:-"default"}

case ${action} in
	default)
		main
		;;
	-l|list)
		install
		;;
	-u|update)
		update
		;;
	-r|remove)
		remove
		;;
	-v|version)
		version
		;;
	-h|help)
		usage 0
		;;
	*)
		usage 1
		;;
esac