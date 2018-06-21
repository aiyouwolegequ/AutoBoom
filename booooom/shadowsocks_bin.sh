#!/bin/bash
export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin

cur_dir=`pwd`

install_shadowsocks(){

    cp -f ${cur_dir}/`basename $0` /usr/local/bin/shadowsocks
}

list_users(){

    if [ ! -f /etc/shadowsocks-libev/config.json ];then
        echo "Error: /etc/shadowsocks-libev/config.json file not found."
        exit 1
    fi

    cat /etc/shadowsocks-libev/config.json |grep -E "server_port|password|method|plugin_opts"|awk '{print $1}'
}

restart(){

    systemctl restart shadowsocks-libev.service
}

status(){

    systemctl status shadowsocks-libev.service -l
}

action=$1
if [ -z ${action} ] && [ "`basename $0`" != "shadowsocks" ]; then
    action=install
fi

case ${action} in
    install)
        install_shadowsocks 2>&1
        ;;
    -l|--list)
        list_users
        ;;
    -r|--restart)
        restart
        ;;
    -s|--status)
        status
        ;;
    *)
        echo "Usage: `basename $0` [-l,--list|-s,--status|-r,--restart]" && exit
        ;;
esac