wget --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/autoboom.sh      
sh autoboom.sh           

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
(10) 安装v2ray        
(11) 安装supervisor        
(12) 安装vlmcsd        
(13) 安装kcptun        
(14) 安装dnscrypt        
(15) 安装pptp        
(16) 安装aide        
(17) 安装pentest tools        

Supervisor 相关命令:        
service supervisord {start|stop|restart|status}        
supervisorctl status        

Aide 相关命令:        
aide --check        
aide --update        

Chkrootkit 相关命令:        
chkrootkit | grep INFECTED        

Rkhunter 相关命令:        
rkhunter --update        
rkhunter --propupd        
rkhunter --check --sk | grep Warning        

Fail2ban 相关命令:        
fail2ban-client status sshd 查看被屏蔽的IP列表        

Lynis 相关命令:        
lynis update info        
lynis audit system        

L2TP 相关命令:        
l2tp -l 列出用户        
l2tp -a 新增用户        
l2tp -d 删除用户        
l2tp -m 修改用户密码        

Kcptun 相关命令:        
supervisorctl {start|stop|restart|status} kcptun        
kcptun uninstall 卸载        
kcptun update 检查更新        
kcptun add 添加一个实例, 多端口加速        
kcptun reconfig 重新配置实例        
kcptun show 显示实例详细配置        
kcptun log 显示实例日志        
kcptun del 删除一个实例        
若不指定 , 则默认为 1        

Dnscrypt-Proxy 相关命令:        
supervisorctl {start|stop|restart|status} dnscrypt-proxy        

Dnscrypt-Wrapper 相关命令:        
dnscrypt-wrapper --show-provider-publickey --provider-publickey-file public.key        
