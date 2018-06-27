# AutoBoom
wget --no-check-certificate https://raw.githubusercontent.com/aiyouwolegequ/AutoBoom/master/autoboom.sh      
sh autoboom.sh           

需要root权限以及zsh！！！             

Usage: autoboom [option]          
[option]: (-l,list|-u,update|-r,remove|-h,help|-v,version)              
-l,list                 列出所有项目                  
-u,update               升级到最新             
-r,remove               卸载         
-h,help                 救命啊                  
-v,version              显示当前版本                

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
(10) 安装dnscrypt-server        
(11) 安装supervisor        
(12) 安装vlmcsd        
(13) 安装brook         
(15) 安装pptp        
(16) 安装aide        
(17) 安装vsftp       
(18) 安装ruby 2.4.1               
(19) 安装docker                 
(20) 安装nmaphenc         
(21) 安装proxychains4             

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
fail2ban-client set ssh unbanip x.x.x.x 解除被屏蔽IP             

Lynis 相关命令:        
lynis update info        
lynis audit system        

L2TP 相关命令:        
l2tp -l 列出用户        
l2tp -a 新增用户        
l2tp -d 删除用户        
l2tp -m 修改用户密码      
l2tp -r 重启服务             

Shadowsocks 相关命令:          
shadowsocks -s 查看状态        
shadowsocks -r 重启服务        
shadowsocks -l 查看配置        

Dnscrypt-Proxy 相关命令:       
docker logs dnscrypt-server    