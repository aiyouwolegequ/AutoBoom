#!/bin/bash
export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

shell_version=v6.1
pre_install_version=v3.4

rootness(){

	if [ $(id -u) != "0" ]; then
		echo "错误:需要root权限！"
		exit 1
	fi
}

check_shell(){

	if [ ! -f "/bin/zsh" ];then
		echo "错误:需要zsh！安装zsh中！"
		rm -rf /var/run/yum.pid
		rpm --quiet --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
		yum install zsh -y
		echo "zsh安装完毕！"
	fi

	if [ `echo $SHELL` != "/bin/zsh" ];then
		echo "请使用chsh -s /bin/zsh && su - 切换到zsh后再执行脚本！"
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
	local host=$(hostname)
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
	echo "net.ipv4.tcp_rmem = 10240 87380 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_wmem = 10240 65536 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_mem = 25600 51200 102400" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syn_retries = 2" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	echo "vm.min_free_kbytes = 65536" >> /etc/sysctl.conf
	echo "fs.file-max = 1024000" >> /etc/sysctl.conf

	cat >> /etc/sysctl.conf<<-EOF
	net.ipv4.conf.all.send_redirects = 0
	net.ipv4.conf.default.send_redirects = 0
	net.ipv4.conf.lo.send_redirects = 0
	net.ipv4.conf.all.rp_filter = 0
	net.ipv4.conf.default.rp_filter = 0
	net.ipv4.conf.lo.rp_filter = 0
	net.ipv4.icmp_echo_ignore_broadcasts = 1
	net.ipv4.icmp_ignore_bogus_error_responses = 1
	net.ipv4.tcp_tw_recycle = 0
	net.ipv4.conf.all.accept_source_route = 1
	net.ipv4.conf.default.accept_source_route = 1
	net.ipv4.conf.all.accept_redirects = 0
	net.ipv4.conf.default.accept_redirects = 0
	EOF

	for each in `ls /proc/sys/net/ipv4/conf/`;
	do
		echo "net.ipv4.conf.${each}.accept_source_route=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.accept_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.send_redirects=0" >> /etc/sysctl.conf
		echo "net.ipv4.conf.${each}.rp_filter=0" >> /etc/sysctl.conf
	done

	sysctl -e -p
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
			echo "端口已被占用, 请重新输入！"
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
				echo "输入有误, 请输入 1~65535 之间的数字！"
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

	local pre_version=`cat /var/autoboom/version.conf | grep pre_install_version | awk '{print $2}'`

	if [ -n "$pre_version"  ]; then
		if [ "$pre_version" != "$pre_install_version" ]; then
			sed -i "s/pre_install_version $pre_version/pre_install_version $pre_install_version/g" /var/autoboom/version.conf
			set_sysctl
			pre_install
		fi
	else
		echo "pre_install_version $pre_install_version" >> /var/autoboom/version.conf
		set_sysctl
		pre_install
	fi
}

pre_install(){

	clear
	echo "#######################################################################"
	echo ""
	echo "预安装相关软件！"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	
	if [ ! -f "/etc/yum.conf.bak" ]; then
		LANG="en_US.UTF-8"

		cat > /etc/resolv.conf<<-EOF
		nameserver 1.1.1.1
		EOF

		cat > /etc/profile<<-EOF
		export PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
		export LC_ALL=en_US.UTF-8
		EOF

		source /etc/profile
		hostnamectl set-hostname ${IP}
		rm -rf /var/run/yum.pid
		cp /etc/yum.conf /etc/yum.conf.bak
		echo "minrate=1" >> /etc/yum.conf
		echo "timeout=300" >> /etc/yum.conf
	fi

	if [ ! -f "/etc/pki/rpm-gpg/RPM-GPG-KEY-elrepo.org" ];then
		rpm --quiet --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
		rpm --quiet -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
	fi

	for a in yum-plugin-fastestmirror yum-utils deltarpm
	do
		if [ `rpm -qa | grep $a | wc -l` -eq 0 ];then
			yum install $a -y
		fi
	done

	yum-complete-transaction --cleanup-only
	yum history redo last
	rm -f /var/lib/rpm/__db*
	rpm --rebuilddb
	yum clean all -y
	yum makecache
	yum update -y
	yum autoremove -y

	if [ $(yum grouplist installed | grep Tools | wc -l) != "1" ];then
		yum groupinstall "Development Tools" -y
		yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm

		for a in man-pages-zh-CN.noarch asciidoc autoconf automake bind-utils bzip2 bzip2-devel c-ares-devel curl finger gawk gcc gcc-c++ gettext git glibc-static iproute libcurl-devel libev-devel libevent-devel libffi-devel libstdc++-static libtool libtool-ltdl-devel lsof m2crypto make mlocate ncurses-devel net-tools openssl-devel patch pcre-devel policycoreutils-python ppp psmisc python-devel python-pip python-setuptools python34 python34-devel readline readline-devel ruby ruby-dev rubygems sqlite-devel swig sysstat tar tk-devel tree unzip vim wget xmlto zlib zlib-devel
		do
			yum install $a -y
		done

		ldconfig
		wget https://bootstrap.pypa.io/get-pip.py
		python get-pip.py
		python3 get-pip.py
		python -m pip install -U pip
		python -m pip install -U distribute
		python3 -m pip install --upgrade pip
		python -m pip install pycurl pygments dnspython gevent selenium BeautifulSoup4 json2html tabulate configparser parse feedparser greenlet
		python3 -m pip install scrapy docopt twisted lxml parsel w3lib cryptography pyopenssl anubis-netsec plecost json2html tabulate
		easy_install supervisor
		updatedb
		locate inittab
		rm -rf get-pip.py
	fi

	if [ ! -f "/usr/local/lib/libevent.so" ];then

		while [ ! -f libevent-2.1.8-stable.tar.gz ] ;
		do
			wget -c https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
		done

		tar zxvf libevent-2.1.8-stable.tar.gz
		pushd libevent-2.1.8-stable
		./configure
		make && make install
		popd
		ldconfig
		m -rf libevent*
	fi

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
	echo "正在升级系统！"
	echo ""
	echo "#######################################################################"
	echo "请耐心等待！"
	cd
	rm -f /var/run/yum.pid
	yum upgrade -y
	yum update -y
	yum autoremove -y
	yum makecache
	yum-complete-transaction --cleanup-only -y
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm --quiet -Va --nofiles --nodigest
	yum clean all -y
	rm -rf /var/cache/yum
	rpm --quiet --rebuilddb
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
	echo "正在升级内核,请在全部脚本完成后重启系统！"
	echo ""
	echo "#######################################################################"
	echo "请耐心等待！"

	if [ `rpm -qa | grep kernel-ml |wc -l` -ne 1 ];then
		yum --enablerepo=elrepo-kernel install kernel-ml -y
	fi

	egrep ^menuentry /etc/grub2.cfg | cut -f 2 -d \'
	grub2-set-default 0
	modprobe tcp_bbr
	modprobe tcp_htcp
	modprobe tcp_hybla
	echo "tcp_bbr" > /etc/modules-load.d/modules.conf
	echo "#######################################################################"
	echo ""
	echo "升级完毕！"
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
				echo "正在更换root密码！"
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
				echo "新建一个非root权限的系统用户！"
				echo ""
				echo "#######################################################################"
				useradd -m ${newusername}
				echo "${newuserpasswd}" | passwd --stdin ${newusername}
				echo "#######################################################################"
				echo ""
				echo "请保存好用户名和密码！"
				echo -e "Username:\033[41;30m${newusername}\033[0m"
				echo -e "Password:\033[41;30m${newuserpasswd}\033[0m"
				echo ""
				echo "#######################################################################"
				echo ""
				any_key_to_continue
				echo ""
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
									echo "输入有误, 重新请输入！"
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
				echo "公钥不能为空！"
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
				echo "请使测试ssh是否恢复正常！"
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
	echo "开始安装ckrootkit和rkhunter！"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	cd

	if [ ! -f "/bin/rkhunter" ]; then
		yum install rkhunter -y
	fi

	if [ ! -f "/usr/local/bin/chkrootkit" ]; then
		wget --tries=3 ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz

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
		echo "正在检测系统，请耐心等待！日志保存在/var/autoboom/log/chkrootkit.log和rkhunter.log"
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
	echo "请稍等！"
	cd

	if [ ! -f "/bin/aide" ]; then
		yum install aide -y
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
	echo "请稍等！"

	if [ ! -f "/usr/bin/fail2ban-client" ]; then
		yum install fail2ban-firewalld -y

		cat > /etc/fail2ban/jail_ssh.local<<-EOF
		[sshd]
		enabled = true
		EOF

		cat > /etc/fail2ban/jail.local<<-EOF
		[DEFAULT]
		banaction = firewallcmd-ipset
		bantime  = 86400
		findtime = 600
		maxretry = 3
		backend = systemd
		ignoreip = 45.77.61.91 43.243.225.16 207.148.74.5 146.0.75.104 202.59.250.145 8.6.8.231 210.92.18.82 210.92.18.73
		EOF

		cat > /etc/fail2ban/jail.d/sshd.local<<-EOF
		[sshd]
		enabled = true
		port = 10010
		logpath  = /var/log/secure
		EOF

		systemctl restart firewalld.service
		systemctl enable firewalld
		systemctl restart fail2ban.service
		systemctl enable fail2ban.service
		systemctl -l | grep fail2ban | awk '{print $1,$2,$3,$4}'
		firewall-cmd --direct --get-all-rules
		ipset list fail2ban-sshd
	fi

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
	echo "请稍等！"
	cd

	if [ ! -f "/usr/local/bin/lynis" ]; then
		git clone https://github.com/CISOfy/lynis

		if [ -d "lynis" ]; then
			mv lynis /usr/local/
			ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
		fi
	fi

	if [ -f "/usr/local/bin/lynis" ]; then
		lynis update info
		echo "#######################################################################"
		echo ""
		echo "正在检测系统，请耐心等待！"
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
	echo "开始安装zsh！"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	cd

	if [ -d "/root/.oh-my-zsh" ]; then
		echo "#######################################################################"
		echo ""
		echo "zsh已安装，请使用upgrade_oh_my_zsh升级zsh！"
		echo ""
		echo "#######################################################################"
		echo ""
	else
		yum install zsh -y
		git clone --depth=1 https://github.com/robbyrussell/oh-my-zsh.git /root/.oh-my-zsh
		cp /root/.oh-my-zsh/templates/zshrc.zsh-template ~/.zshrc
		cd /root/.oh-my-zsh/themes
		git clone https://github.com/dracula/zsh.git
		mv zsh/dracula.zsh-theme .
		rm -rf zsh
		cd /root/.oh-my-zsh/plugins
		git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
		git clone https://github.com/zsh-users/zsh-autosuggestions.git
		git clone https://github.com/zsh-users/zsh-history-substring-search.git

		cat > /root/.zshrc <<-EOF
		export ZSH=/root/.oh-my-zsh
		ZSH_THEME="dracula"
		plugins=(sudo zsh-syntax-highlighting git autojump web-search zsh_reload colored-man-pages zsh-autosuggestions zsh-history-substring-search)
		source /root/.oh-my-zsh/oh-my-zsh.sh
		export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
		alias vizsh="vim ~/.zshrc"
		alias sourcezsh="source ~/.zshrc"
		alias cman="man -M /usr/share/man/zh_CN"
		EOF

		chsh -s /bin/zsh root
		echo "#######################################################################"
		echo ""
		echo -e "请手动输入\033[41;30mexit\033[0m继续执行脚本...！"
		echo "千万不要按Ctrl + C退出脚本!!!"
		echo ""
		echo "#######################################################################"
		env zsh
		echo "#######################################################################"
		echo ""
		echo "Zsh安装完毕，脚本完成后使用env zsh手动切换shell为zsh."
		echo ""
		echo "#######################################################################"
		echo ""
	fi

	auto_continue
}

install_shadowsocks(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Shadowsocks！"
	echo ""
	echo "#######################################################################"
	echo ""
	sspasswd=`randpasswd`
	local listen_port=9999
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

	pip install --upgrade pip
	pip install m2crypto

	wget -c -O libsodium.tar.gz https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
	tar zxvf libsodium.tar.gz
	pushd libsodium-stable
	./configure
	make && make install
	popd
	echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	ldconfig
	rm -rf libsodium*

	wget -c https://tls.mbed.org/download/mbedtls-2.11.0-gpl.tgz
	tar xvf mbedtls-2.11.0-gpl.tgz
	pushd mbedtls-2.11.0
	make SHARED=1 CFLAGS=-fPIC
	make DESTDIR=/usr install
	popd
	ldconfig
	rm -rf mbedtls*

	git clone https://github.com/shadowsocks/simple-obfs.git
	pushd simple-obfs
	git submodule update --init --recursive
	./autogen.sh
	./configure && make
	make install
	popd
	rm -rf simple-obfs

	cd /etc/yum.repos.d/
	curl -O https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/repo/epel-7/librehat-shadowsocks-epel-7.repo
	yum install shadowsocks-libev rng-tools -y

	cat >/etc/shadowsocks-libev/config.json<<-EOF
	{
	"server":"0.0.0.0",
	"server_port":"9999",
	"password":"${sspasswd}",
	"nameserver": "1.1.1.1",
	"timeout":"600",
	"method":"aes-256-gcm",
	"plugin":"obfs-server",
	"plugin_opts":"obfs=tls"
	}
	EOF

	cat >/etc/sysconfig/shadowsocks-libev<<-EOF
	START=yes
	CONFFILE="/etc/shadowsocks-libev/config.json"
	DAEMON_ARGS="-u -d 1.1.1.1 --fast-open --reuse-port --mtu 1492 --no-delay"
	MAXFD=32768
	EOF

	systemctl daemon-reload
	systemctl restart shadowsocks-libev.service
	systemctl enable shadowsocks-libev.service
	systemctl status shadowsocks-libev.service
	systemctl -l | grep shadowsocks | awk '{print $1,$2,$3,$4}'
	wget --tries=3 https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/shadowsocks_bin.sh
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
	echo -e "Encryption:\033[41;30maes-256-gcm\033[0m"
	echo -e "plugin_opts:\033[41;30mobfs=tls\033[0m"
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_pptp(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始配置PPTP VPN:"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	pptpuser=`randusername`
	pptppasswd=`randpasswd`
	yum install pptpd -y
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
	systemctl -l | grep pptpd | awk '{print $1,$2,$3,$4}'
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
	yum install libreswan xl2tpd -y
	sysctl -p
	systemctl start ipsec
	systemctl start xl2tpd
	systemctl enable ipsec
	systemctl enable xl2tpd
	systemctl -l | grep ipsec | awk '{print $1,$2,$3,$4}'
	systemctl -l | grep xl2tpd | awk '{print $1,$2,$3,$4}'

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
	systemctl -l | grep ipsec | awk '{print $1,$2,$3,$4}'
	systemctl -l | grep xl2tpd | awk '{print $1,$2,$3,$4}'
	cd
	wget --tries=3 https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/l2tp_bin.sh
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

install_supervisor(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装Supervisor"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

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

		wget --tries=3 -O "$file" --no-check-certificate "$url"

		if [ "$?" != "0" ] || [ -n "$verify_cmd" ] && ! verify_file; then
			retry=$(expr $retry + 1)
			download_file_to_path
		fi
	}

	config_install_supervisor(){

		if [ ! -d "/etc/supervisor/conf.d" ]; then
			mkdir -p /etc/supervisor/conf.d
		fi

		if [ ! -f "/usr/local/bin/supervisord" ]; then
			ln -s "$(command -v supervisord)" '/usr/local/bin/supervisord' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/supervisorctl" ]; then
			ln -s "$(command -v supervisorctl)" '/usr/local/bin/supervisorctl' 2>/dev/null
		fi

		if [ ! -f "/usr/local/bin/pidproxy" ]; then
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
	echo "开始安装Vlmcsd"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

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

	wget --tries=3 -O /usr/local/bin/vlmcsd --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/vlmcsd.server
	chmod 0755 /usr/local/bin/vlmcsd
	wget --tries=3 -O /usr/local/bin/vlmcsdmulti-x64-musl-static --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/booooom/vlmcsdmulti-x64-musl-static
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
	systemctl -l | grep vlmcsd | awk '{print $1,$2,$3,$4}'
	echo "#######################################################################"
	echo ""
	echo "Vlmcsd安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_vsftp(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始安装vsftp"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	yum -y install vsftpd
	sed -i 's/^anonymous_enable=YES/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf
	echo chroot_local_user=YES >> /etc/vsftpd/vsftpd.conf
	echo allow_writeable_chroot=YES >> /etc/vsftpd/vsftpd.conf
	echo pasv_enable=YES >> /etc/vsftpd/vsftpd.conf
	echo pasv_min_port=40000 >> /etc/vsftpd/vsftpd.conf
	echo pasv_max_port=40100 >> /etc/vsftpd/vsftpd.conf
	firewall-cmd --permanent --add-service=ftp
	firewall-cmd --reload
	useradd -d /home/ftpd -m uftp -s /sbin/nologin
	echo ftpddptf123321 | passwd uftp --stdin
	systemctl start vsftpd.service
	systemctl -l | grep vsftpd | awk '{print $1,$2,$3,$4}'
	echo "#######################################################################"
	echo ""
	echo "vsftp安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_ruby(){

	echo "#######################################################################"
	echo ""
	echo "开始安装ruby 2.4.1"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	curl -sSL https://rvm.io/mpapis.asc | gpg --import -
	curl -L get.rvm.io | bash -s stable
	source /etc/profile.d/rvm.sh
	rvm reload
	rvm requirements run
	rvm install "ruby-2.4.1"
	rvm use 2.4.1 --default
	ruby -v
	gem -v
	echo "#######################################################################"
	echo ""
	echo "ruby 2.4.1安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_docker(){

	echo "#######################################################################"
	echo ""
	echo "开始安装docker"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	yum remove docker docker-common docker-selinux docker-engine -y
	yum install yum-utils device-mapper-persistent-data lvm2 -y
	yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
	yum-config-manager --enable docker-ce-edge
	yum-config-manager --enable docker-ce-test
	yum-config-manager --disable docker-ce-edge
	yum install docker-ce -y
	systemctl start docker
	systemctl enable docker
	systemctl -l | grep docker.service | awk '{print $1,$2,$3,$4}'
	echo "#######################################################################"
	echo ""
	echo "docker安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_dnscrypt(){

	echo "#######################################################################"
	echo ""
	echo "开始安装dnscrypt"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

	if [ -z `command -v docker` ]; then
		echo "请先安装docker!"
		any_key_to_continue
		mainmenu
	elif [ `systemctl -l | grep docker.service | awk '{print $1,$2,$3,$4}' | grep running | wc -l` -eq 0 ]; then
		systemctl enable docker
		systemctl restart docker
	fi

	local listen_port=5443
	read -p "默认设置dnscrypt端口为${listen_port}，是否需要更换端口? (y/n) [默认=n]:" input
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
				firewall-cmd --permanent --add-port=${listen_port}/tcp
				firewall-cmd --permanent --add-port=${listen_port}/udp
				firewall-cmd --reload
			fi
			;;
	esac

	docker run --name=dnscrypt -p ${listen_port}:443/udp -p ${listen_port}:443/tcp --net=host \
	jedisct1/dnscrypt-server init -N gov.us -E ${IP}:5443
	docker start dnscrypt
	docker update --restart=unless-stopped dnscrypt
	echo "#######################################################################"
	echo ""
	echo "dnscrypt安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_dns(){

	echo "#######################################################################"
	echo ""
	echo "开始安装dns"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

	yum install bind -y
	systemctl start named
	cat > /etc/named.conf <<-EOF
	options {
			listen-on port 53 { any; };
			listen-on-v6 port 53 { none; };
			directory "/var/named";
			dump-file "/var/named/data/cache_dump.db";
			statistics-file "/var/named/data/named_stats.txt";
			memstatistics-file "/var/named/data/named_mem_stats.txt";
			allow-query { any; };
			allow-recursion { any; };

			forwarders {
				8.8.4.4;
				8.8.8.8;
			};
			forward only;
			recursion yes;
			dnssec-enable yes;
			dnssec-validation yes;
			bindkeys-file "/etc/named.iscdlv.key";
			managed-keys-directory "/var/named/dynamic";
			pid-file "/run/named/named.pid";
			session-keyfile "/run/named/session.key";
	};

	logging {
			channel query_log {
				file "data/query.log" versions 100 size 500m;
				severity debug 3;
				print-time yes;
				print-category  yes;
			};
			category queries {
				query_log;
			};
	};
	EOF

	systemctl restart named
	firewall-cmd --permanent --add-service=dns
	firewall-cmd --reload
	echo "#######################################################################"
	echo ""
	echo "dns安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	any_key_to_continue
}

install_brook(){

	echo "#######################################################################"
	echo ""
	echo "开始安装brook"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

	if [ -z `command -v docker` ]; then
		echo "请先安装docker!"
		any_key_to_continue
		mainmenu
	elif [ `systemctl -l | grep docker.service | awk '{print $1,$2,$3,$4}' | grep running | wc -l` -eq 0 ]; then
		systemctl enable docker
		systemctl restart docker
	fi

	brookpasswd=`randpasswd`
	local listen_port=6443
	read -p "默认设置brook端口为${listen_port}，是否需要更换端口? (y/n) [默认=n]:" input
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
				firewall-cmd --permanent --add-port=${listen_port}/tcp
				firewall-cmd --permanent --add-port=${listen_port}/udp
				firewall-cmd --reload
			fi
			;;
	esac
	
	docker run --name=brook -d -e "ARGS=server -l :6060 -p ${brookpasswd}" -p ${listen_port}:6060/tcp -p ${listen_port}:6060/udp chenhw2/brook
	docker start brook
	docker update --restart=unless-stopped brook
	echo "#######################################################################"
	echo ""
	echo "brook安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	echo "brook的相关配置:"
	echo -e "Password:\033[41;30m${brookpasswd}\033[0m"
	echo -e "Port:\033[41;30m${listen_port}\033[0m"
	echo ""
	echo "#######################################################################"
	any_key_to_continue
}

install_kcptun(){

	echo "#######################################################################"
	echo ""
	echo "开始安装kcptun"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

	if [ -z `command -v docker` ]; then
		echo "请先安装docker!"
		any_key_to_continue
		mainmenu
	elif [ ! -e "/etc/shadowsocks-libev/config.json" ]; then
		echo "请先安装shadowsocks!"
		any_key_to_continue
		mainmenu
	elif [ `systemctl -l | grep shadowsocks-libev.service | awk '{print $1,$2,$3,$4}' | grep running | wc -l` -eq 0 ]; then
		systemctl enable shadowsocks-libev.service
		systemctl restart shadowsocks-libev.service
	fi

	kcppasswd=`randpasswd`
	ss_port=`shadowsocks -l | grep port | awk -F "\"" '{print $4}'`
	local listen_port=8443
	read -p "默认设置kcptun端口为${listen_port}，是否需要更换端口? (y/n) [默认=n]:" input
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
				firewall-cmd --permanent --add-port=${listen_port}/tcp
				firewall-cmd --permanent --add-port=${listen_port}/udp
				firewall-cmd --reload
			fi
			;;
	esac

	docker run --name kcptun -d -p ${listen_port}:${listen_port} xtaci/kcptun server -t 0.0.0.0:${ss_port} -l :${listen_port} -key ${kcppasswd} -mtu 1350 -mode fast3
	docker start kcptun
	docker update --restart=unless-stopped kcptun
	echo "#######################################################################"
	echo ""
	echo "kcptun安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	echo "#######################################################################"
	echo ""
	echo "kcptun的相关配置:"
	echo -e "password:\033[41;30m${kcppasswd}\033[0m"
	echo -e "port:\033[41;30m${listen_port}\033[0m"
	echo -e "encryption:\033[41;30maes\033[0m"
	echo -e "mode:\033[41;30mfast3\033[0m"
	echo -e "sndwnd:\033[41;30m1024\033[0m"
	echo -e "rcvwnd:\033[41;30m1024\033[0m"
	echo -e "acknodelay:\033[41;30mfalse\033[0m"
	echo -e "compression:\033[41;30mture\033[0m"
	echo -e "mtu:\033[41;30m1350\033[0m"
	echo -e "datashard:\033[41;30m10\033[0m"
	echo -e "parityshard:\033[41;30m3\033[0m"
	echo -e "dscp:\033[41;30m0\033[0m"
	echo -e "keepalive:\033[41;30m10\033[0m"
	echo ""
	echo "#######################################################################"
	any_key_to_continue
}

install_v2ray(){

	echo "#######################################################################"
	echo ""
	echo "开始安装v2ray"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"

	if [ -z `command -v docker` ]; then
		echo "请先安装docker!"
		any_key_to_continue
		mainmenu
	elif [ `systemctl -l | grep docker.service | awk '{print $1,$2,$3,$4}' | grep running | wc -l` -eq 0 ]; then
		systemctl enable docker
		systemctl restart docker
	fi

	if [ -z `command -v docker-compose` ]; then
		curl -L https://github.com/docker/compose/releases/download/1.22.0-rc1/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
		chmod +x /usr/local/bin/docker-compose
	fi

	local domain=
	local email=
	local input=

	read -p "(请输入域名): " input
		if [ -n "$input" ]; then
			domain="$input"
		else
			domain=www.google.com
		fi

	read -p "(请输入邮箱): " input
		if [ -n "$input" ]; then
			domain="$input"
		else
			email=no-reply@accounts.google.com
		fi

	uuid=`cat /proc/sys/kernel/random/uuid`
	mkdir -p /opt/v2ray/v2ray_logs
	mkdir -p /opt/v2ray/nginx/vhost.d
	mkdir -p /etc/v2ray
	cd /opt/v2ray

	if [ ! -f "nginx.tmpl" ]; then
		curl -L https://raw.githubusercontent.com/jwilder/nginx-proxy/master/nginx.tmpl > /opt/v2ray/nginx.tmpl
		firewall-cmd --permanent --remove-service=dhcpv6-client
		firewall-cmd --permanent --add-service=http
		firewall-cmd --permanent --add-service=https
		firewall-cmd --reload
	fi

	cat > /etc/v2ray/config.json<<-EOF
	{
		"log": {
			"access": "/var/log/v2ray/access.log",
			"error": "/var/log/v2ray/error.log",
			"loglevel": "warning"
		},
		"inbound": {
			"port": 19487,
			"protocol": "vmess",
			"settings": {
				"clients": [
					{
						"id": "${uuid}",
						"level": 1,
						"alterId": 9487
					}
				]
			},
			"streamSettings": {
				"network": "ws",
				"wsSettings": {
					"connectionReuse": false,
					"path": "/"
					}
			},
			"detour": {
				"to": "vmess-detour"
			}
		},
		"outbound": {
			"protocol": "freedom",
			"settings": {}
		},
		"inboundDetour": [
			{
				"protocol": "vmess",
				"port": "45000-45999",
				"tag": "vmess-detour",
				"settings": {},
				"allocate": {
					"strategy": "random",
					"concurrency": 5,
					"refresh": 5
				},
				"streamSettings": {
					"network": "ws",
					"wsSettings": {
						"connectionReuse": false,
						"path": "/"
					}
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
				"rules": [{
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
				}]
			}
		}
	}
	EOF

	cat > /opt/v2ray/docker-compose.yml<<-EOF
	version: '3'
	services:
	  v2ray:
	    container_name: v2ray
	    image: v2ray/official
	    restart: unless-stopped
	    command: v2ray -config=/etc/v2ray/config.json
	    expose:
	      - "19487"
	    ports:
	      - "19487:19487"
	      - "19487:19487/udp"
	    volumes:
	      - /opt/v2ray/v2ray_logs:/var/log/v2ray/
	      - /etc/v2ray:/etc/v2ray/
	    environment:
	      - "VIRTUAL_HOST=${domain}"
	      - "VIRTUAL_PORT=19487"
	      - "LETSENCRYPT_HOST=${domain}"
	      - "LETSENCRYPT_EMAIL=${email}"

	  nginx:
	    image: nginx
	    labels:
	      com.github.jrcs.letsencrypt_nginx_proxy_companion.nginx_proxy: "true"
	    container_name: nginx
	    restart: unless-stopped
	    ports:
	      - "80:80"
	      - "443:443"
	    volumes:
	      - /opt/v2ray/nginx/conf.d:/etc/nginx/conf.d
	      - /opt/v2ray/nginx/vhost.d:/etc/nginx/vhost.d
	      - /opt/v2ray/nginx/html:/usr/share/nginx/html
	      - /opt/v2ray/nginx/certs:/etc/nginx/certs:ro

	  nginx-gen:
	    image: jwilder/docker-gen
	    command: -notify-sighup nginx -watch -wait 5s:30s /etc/docker-gen/templates/nginx.tmpl /etc/nginx/conf.d/default.conf
	    container_name: nginx-gen
	    restart: unless-stopped
	    volumes:
	      - /opt/v2ray/nginx/conf.d:/etc/nginx/conf.d
	      - /opt/v2ray/nginx/vhost.d:/etc/nginx/vhost.d
	      - /opt/v2ray/nginx/html:/usr/share/nginx/html
	      - /opt/v2ray/nginx/certs:/etc/nginx/certs:ro
	      - /var/run/docker.sock:/tmp/docker.sock:ro
	      - /opt/v2ray/nginx.tmpl:/etc/docker-gen/templates/nginx.tmpl:ro

	  nginx-letsencrypt:
	    image: jrcs/letsencrypt-nginx-proxy-companion
	    container_name: nginx-letsencrypt
	    restart: unless-stopped
	    volumes:
	      - /opt/v2ray/nginx/conf.d:/etc/nginx/conf.d
	      - /opt/v2ray/nginx/vhost.d:/etc/nginx/vhost.d
	      - /opt/v2ray/nginx/html:/usr/share/nginx/html
	      - /opt/v2ray/nginx/certs:/etc/nginx/certs:rw
	      - /var/run/docker.sock:/var/run/docker.sock:ro
	    environment:
	      NGINX_DOCKER_GEN_CONTAINER: "nginx-gen"
	      NGINX_PROXY_CONTAINER: "nginx"
	EOF

	cat > /opt/v2ray/nginx/vhost.d/${domain}_location<<-EOF
	proxy_redirect off;
	proxy_http_version 1.1;
	proxy_set_header Upgrade \$http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_set_header Host \$http_host;
	if (\$http_upgrade = "websocket" ) {
	    proxy_pass http://v2ray:19487;
	}
	EOF

	docker-compose up -d
	echo "#######################################################################"
	echo ""
	echo "v2ray安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	echo "v2ray的相关配置:"
	echo -e "User ID:\033[41;30m${uuid}\033[0m"
	echo -e "alterId:\033[41;30m9487\033[0m"
	echo -e "Port:\033[41;30m443\033[0m"
	echo -e "Security:\033[41;30maes-128-cfb\033[0m"
	echo -e "Network:\033[41;30mwebsocket\033[0m"
	echo -e "path:\033[41;30m/\033[0m"
	echo ""
	echo "#######################################################################"
	any_key_to_continue
}

install_nmap_nc(){

	echo "#######################################################################"
	echo ""
	echo "开始安装nmap,nc"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	wget https://nmap.org/dist/ncat-7.60-1.x86_64.rpm
	wget https://nmap.org/dist/nmap-7.60-1.x86_64.rpm
	rpm -i ncat-7.60-1.x86_64.rpm nmap-7.60-1.x86_64.rpm
	ln -s /usr/bin/ncat /usr/bin/nc
	rm -rf ncat-7.60-1.x86_64.rpm nmap-7.60-1.x86_64.rpm
	echo "#######################################################################"
	echo ""
	echo "nmap,nc安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
	auto_continue
}

install_proxychains4(){

	echo "#######################################################################"
	echo ""
	echo "开始安装proxychains4"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	git clone https://github.com/rofl0r/proxychains-ng.git /usr/src/proxychains-ng
	cd /usr/src/proxychains-ng
	./configure
	make && make install
	./tools/install.sh -D -m 644 libproxychains4.so /usr/local/lib/libproxychains4.so
	./tools/install.sh -D -m 755 proxychains4 /usr/local/bin/proxychains4
	./tools/install.sh -D -m 644 src/proxychains.conf /usr/local/etc/proxychains.conf
	cd
	echo "#######################################################################"
	echo ""
	echo "proxychains4安装完毕."
	echo ""
	echo "#######################################################################"
	echo ""
}

clearsystem(){

	clear
	echo "#######################################################################"
	echo ""
	echo "开始清理系统"
	echo ""
	echo "#######################################################################"
	echo "请稍等！"
	cd

	if [ -f ./autoboom.sh ]; then
		rm -rf ./autoboom.sh
	fi

	yum autoremove -y
	yum makecache
	yum-complete-transaction --cleanup-only -y
	package-cleanup --dupes
	package-cleanup --cleandupes
	package-cleanup --problems
	rpm --quiet -Va --nofiles --nodigest
	yum clean all -y
	rm -rf /var/cache/yum
	rpm --quiet --rebuilddb
	echo "#######################################################################"
	echo ""
	echo "清理完毕！"
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

	pre_check
	mainmenu
}

update(){

	echo "Check for update..."
	wget -q --tries=3 --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/autoboom.sh
	chmod +x autoboom.sh
	local version=`grep shell_version -m1 autoboom.sh | awk -F = '{print $2}'`

	if [ -f "/var/autoboom/version.conf" ]; then
		local pre_version=`cat /var/autoboom/version.conf | grep shell_version | awk '{print $2}'`
		if [ "$pre_version" = "$version" ]; then
			echo "no update is available - -#"
			rm -rf ./autoboom.sh
		else
			if [ -f "/usr/local/bin/autoboom" ]; then
				rm -rf /usr/local/bin/autoboom
			fi

			mv -f autoboom.sh /usr/local/bin/autoboom
			echo "update success ^_^"
			sed -i "s/shell_version $pre_version/shell_version $version/g" /var/autoboom/version.conf
			rm -rf ./autoboom.sh
		fi
	fi
}

remove(){

	rm -rf /usr/local/bin/autoboom /var/autoboom/version.conf
}

version(){

	echo "AutoBoom $shell_version"
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
	install_supervisor
	install_vlmcsd
	install_aide
	install_vsftp
	install_ruby
	install_docker
	install_nmap_nc
	install_proxychains4
	install_dnscrypt
	install_brook
	install_dns
	clearsystem
	finally
}

finally(){

	clear
	echo "#######################################################################"
	echo ""
	echo "搞定了，搞定了，搞定了！"
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
	echo -e "Port:\033[41;30m${listen_port}\033[0m"
	echo -e "Password:\033[41;30m${sspasswd}\033[0m"
	echo -e "Encryption:\033[41;30maes-256-gcm\033[0m"
	echo -e "plugin_opts:\033[41;30mobfs=tls\033[0m"
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
			submenu1
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
			submenu1
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
	local a1="\033[41;30m"
	local a2="\033[0m"
	local a4=
	local a5=
	local a6=
	local a7=
	local a8=
	local a9=
	local a10=
	local a11=
	local a12=
	local a13=
	local a14=
	local a15=
	local a16=
	local a17=
	local a18=
	local a19=
	local a20=
	local a21=
	local a22=
	local a23=

	if [ ! -f "/bin/rkhunter" ] && [ ! -f "/usr/local/bin/chkrootkit" ]; then
		a4=`echo "(4) 安装ckrootkit和rkhunter"`
	else
		a4=`echo -e "(4) $a1已安装ckrootkit和rkhunter$a2"`
	fi

	if [ ! -f "/usr/bin/fail2ban-client" ]; then
		a5=`echo "(5) 安装fail2ban"`
	else
		a5=`echo -e "(5) $a1已安装fail2ban$a2"`
	fi

	if [ ! -f "/usr/local/bin/lynis" ]; then
		a6=`echo "(6) 安装lynis"`
	else
		a6=`echo -e "(6) $a1已安装lynis$a2"`
	fi

	if [ ! -d "/root/.oh-my-zsh" ]; then
		a7=`echo "(7) 安装zsh"`
	else
		a7=`echo -e "(7) $a1已安装zsh$a2"`
	fi

	if [ ! -e "/etc/shadowsocks-libev/config.json" ]; then
		a8=`echo "(8) 安装shadowsocks"`
	else
		a8=`echo -e "(8) $a1已安装shadowsocks$a2"`
	fi

	if [ -z `command -v l2tp` ]; then
		a9=`echo "(9) 安装l2tp"`
	else
		a9=`echo -e "(9) $a1已安装l2tp$a2"`
	fi

	if [ -z `command -v docker` ]; then
		a10=`echo "(10) 安装dnscrypt"`
	elif [ `docker images | grep dnscrypt-server | wc -l` -eq 1 ] ; then
		a10=`echo -e "(10) $a1已安装dnscrypt$a2"`
	else
		a10=`echo "(10) 安装dnscrypt"`
	fi

	if [ ! -e "/etc/supervisor/supervisord.conf" ]; then
		a11=`echo "(11) 安装supervisor"`
	else
		a11=`echo -e "(11) $a1已安装supervisor$a2"`
	fi

	if [ -z `command -v vlmcsd` ]; then
		a12=`echo "(12) 安装vlmcsd"`
	else
		a12=`echo -e "(12) $a1已安装vlmcsd$a2"`
	fi

	if [ -z `command -v docker` ]; then
		a13=`echo "(13) 安装brook"`
	elif [ `docker images | grep brook | wc -l` -eq 1 ] ; then
		a13=`echo -e "(13) $a1已安装brook$a2"`
	else
		a13=`echo "(13) 安装brook"`
	fi

	if [ -z `command -v docker` ]; then
		a14=`echo "(14) 安装kcptun"`
	elif [ `docker images | grep kcptun | wc -l` -eq 1 ] ; then
		a14=`echo -e "(14) $a1已安装kcptun$a2"`
	else
		a14=`echo "(14) 安装kcptun"`
	fi

	if [ ! -e "/etc/ppp/options.pptpd" ]; then
		a15=`echo "(15) 安装pptp"`
	else
		a15=`echo -e "(15) $a1已安装pptp$a2"`
	fi

	if [ -z `command -v aide` ]; then
		a16=`echo "(16) 安装aide"`
	else
		a16=`echo -e "(16) $a1已安装aide$a2"`
	fi

	if [ ! -e "/etc/vsftpd/vsftpd.conf" ]; then
		a17=`echo "(17) 安装vsftp"`
	else
		a17=`echo -e "(17) $a1已安装vsftp$a2"`
	fi

	if [ ! -e "/usr/local/rvm/rubies/ruby-2.4.1/bin/ruby" ]; then
		a18=`echo "(18) 安装ruby 2.4.1"`
	else
		a18=`echo -e "(18) $a1已安装ruby 2.4.1$a2"`
	fi

	if [ -z `command -v docker` ]; then
		a19=`echo "(19) 安装docker"`
	else
		a19=`echo -e "(19) $a1已安装docker$a2"`
	fi

	if [ -z `command -v nmap` ] && [ -z `command -v nc` ]; then
		a20=`echo "(20) 安装nmap和nc"`
	else
		a20=`echo -e "(20) $a1已安装nmap和nc$a2"`
	fi

	if [ -z `command -v proxychains4` ]; then
		a21=`echo "(21) 安装proxychains4"`
	else
		a21=`echo -e "(21) $a1已安装proxychains4$a2"`
	fi

	if [ -z `command -v docker` ]; then
		a22=`echo "(22) 安装v2ray"`
	elif [ `docker images | grep v2ray | wc -l` -eq 1 ] ; then
		a22=`echo -e "(22) $a1已安装v2ray$a2"`
	else
		a22=`echo "(22) 安装v2ray"`
	fi

	if [ -z `command -v named` ]; then
		a23=`echo "(23) 安装dns"`
	else
		a23=`echo -e "(23) $a1已安装dns$a2"`
	fi

	echo "#######################################################################"
	echo ""
	echo "进入正式安装......"
	echo ""
	echo "(0) 退出"
	echo "(1) 默认全部安装"
	echo "(2) 升级系统，升级内核，清理系统"
	echo "(3) 更换root密码，新增ssh免密码验证用户"
	echo "$a4"
	echo "$a5"
	echo "$a6"
	echo "$a7"
	echo "$a8"
	echo "$a9"
	echo "$a10"
	echo "$a11"
	echo "$a12"
	echo "$a13"
	echo "$a14"
	echo "$a15"
	echo "$a16"
	echo "$a17"
	echo "$a18"
	echo "$a19"
	echo "$a20"
	echo "$a21"
	echo "$a22"
	echo "$a23"
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
			install_dnscrypt
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
			install_brook
			mainmenu
			;;
		14)
			install_kcptun
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
			install_vsftp
			mainmenu
			;;
		18)
			install_ruby
			mainmenu
			;;
		19)
			install_docker
			mainmenu
			;;
		20)
			install_nmap_nc
			mainmenu
			;;
		21)
			install_proxychains4
			mainmenu
			;;
		22)
			install_v2ray
			mainmenu
			;;
		23)
			install_dns
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
	echo "CentOS 7 服务器一键部署脚本！！！"
	echo "autoboom $shell_version"
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
check_shell
IP=$(curl -s ipinfo.io | sed -n 2p | awk -F \" '{print $4}')

if [ ! -f "/usr/local/bin/autoboom" ]; then
	mv -f autoboom.sh /usr/local/bin/autoboom
	chmod +x /usr/local/bin/autoboom
fi

if [ ! -f "/var/autoboom/version.conf" ]; then
	mkdir -p /var/autoboom/
	touch /var/autoboom/version.conf
	echo "shell_version $shell_version" > /var/autoboom/version.conf
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