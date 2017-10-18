wget --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/CentOS_7-script/master/gogogo.sh      
chmod +x gogogo.sh    
./gogogo.sh      

(0) 退出           
(1) 默认全部安装        
(2) 升级系统，升级内核，清理系统         
(3) 更换root密码，新增ssh免密码验证用户      
(4) 安装ckrootkit和rkhunter       
(5) 安装fail2ban      
(6) 安装lynis      
(7) 安装zsh      
(8) 安装shadowsocks      
(9) 安装l2tp       
(10) 安装vlmcsd      
(11) 安装v2ray       
(12) 安装supervisor       
(13) 安装kcptun      
(14) 安装dnscrypt         

l2tp -l 	列出用户       
l2tp -a 	新增用户       
l2tp -d 	删除用户       
l2tp -m 	修改用户密码       

kcptun uninstall      卸载      
kcptun update         检查更新       
kcptun add            添加一个实例, 多端口加速      
kcptun reconfig <id>  重新配置实例      
kcptun show <id>      显示实例详细配置            
kcptun log <id>       显示实例日志         
kcptun del <id>       删除一个实例      
若不指定 <id>, 则默认为 1        
  

Supervisor 命令:      
service supervisord {start|stop|restart|status}        

Kcptun 相关命令:      
supervisorctl {start|stop|restart|status} kcptun<id>      

Dnscrypt 相关命令:    
supervisorctl {start|stop|restart|status} dnscrypt       
