	#!/usr/bin/env bash
	PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
	export PATH

	cur_dir=`pwd`

	install_l2tp(){

	    cp -f ${cur_dir}/`basename $0` /usr/bin/l2tp
	}

	rand(){

	    str=""
	    cat /dev/urandom | head -n 10 | md5sum | awk -F ' ' '{print $1}' | cut -c-12
	    echo ${str}
	}

	list_users(){

	    if [ ! -f /etc/ppp/chap-secrets ];then
	        echo "Error: /etc/ppp/chap-secrets file not found."
	        exit 1
	    fi

	    local line="+-------------------------------------------+\n"
	    local string=%20s
	    printf "${line}|${string} |${string} |\n${line}" Username Password
	    grep -v "^#" /etc/ppp/chap-secrets | awk '{printf "|'${string}' |'${string}' |\n", $1,$3}'
	    printf ${line}
	}

	add_user(){

	    while :
	    do
	        read -p "Please input your Username:" user
	        if [ -z ${user} ]; then
	            echo "Username can not be empty"
	        else
	            grep -w "${user}" /etc/ppp/chap-secrets > /dev/null 2>&1
	            if [ $? -eq 0 ];then
	                echo "Username (${user}) already exists. Please re-enter your username."
	            else
	                break
	            fi
	        fi
	    done

	    pass=`rand`
	    echo "Please input ${user}'s password:"

	    read -p "(Default Password: ${pass}):" tmppass
	    [ ! -z ${tmppass} ] && pass=${tmppass}
	    echo "${user}    l2tpd    ${pass}    *" >> /etc/ppp/chap-secrets
	    echo "Username (${user}) add completed."
	}

	del_user(){
	    while :
	    do
	        read -p "Please input Username you want to delete it:" user
	        if [ -z ${user} ]; then
	            echo "Username can not be empty"
	        else
	            grep -w "${user}" /etc/ppp/chap-secrets >/dev/null 2>&1
	            if [ $? -eq 0 ];then
	                break
	            else
	                echo "Username (${user}) is not exists. Please re-enter your username."
	            fi
	        fi
	    done

	    sed -i "/^\<${user}\>/d" /etc/ppp/chap-secrets
	    echo "Username (${user}) delete completed."
	}

	mod_user(){
	    while :
	    do
	        read -p "Please input Username you want to change password:" user
	        if [ -z ${user} ]; then
	            echo "Username can not be empty"
	        else
	            grep -w "${user}" /etc/ppp/chap-secrets >/dev/null 2>&1
	            if [ $? -eq 0 ];then
	                break
	            else
	                echo "Username (${user}) is not exists. Please re-enter your username."
	            fi
	        fi
	    done

	    pass=`rand`
	    echo "Please input ${user}'s new password:"

	    read -p "(Default Password: ${pass}):" tmppass
	    [ ! -z ${tmppass} ] && pass=${tmppass}
	    sed -i "/^\<${user}\>/d" /etc/ppp/chap-secrets
	    echo "${user}    l2tpd    ${pass}    *" >> /etc/ppp/chap-secrets
	    echo "Username ${user}'s password has been changed."
	}

	action=$1
	if [ -z ${action} ] && [ "`basename $0`" != "l2tp" ]; then
	    action=install
	fi

	case ${action} in
	    install)
	        install_l2tp 2>&1
	        ;;
	    -l|--list)
	        list_users
	        ;;
	    -a|--add)
	        add_user
	        ;;
	    -d|--del)
	        del_user
	        ;;
	    -m|--mod)
	        mod_user
	        ;;
	    -h|--help)
	        echo "Usage: `basename $0` -l,--list   List all users"
	        echo "       `basename $0` -a,--add    Add a user"
	        echo "       `basename $0` -d,--del    Delete a user"
	        echo "       `basename $0` -m,--mod    Modify a user password"
	        echo "       `basename $0` -h,--help   Print this help information"
	        ;;
	    *)
	        echo "Usage: `basename $0` [-l,--list|-a,--add|-d,--del|-m,--mod|-h,--help]" && exit
	        ;;
	esac