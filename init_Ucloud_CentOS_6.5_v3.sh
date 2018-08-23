#!/bin/bash
#create by ray on 2016-04-26
VIRTUAL_ROUTE=0
DEFAULT_INIT=0
INSTALL_SOFT=0
SHOW_REPOLIST=0
INIT_LOG_FILE="/tmp/init_log_file.log"

if [[ "$@" =~ "-V" ]];then
	VIRTUAL_ROUTE=1
fi

SCRIPTS_NAME=$0
SCRIPTS_AGRS=$*

HMS_IP="10.10.114.116"

#监控服务器地址
#if [ `ping monitor.whaley.cn -c 1 -w 1 | grep 100%  | wc -l` -ge 1 ];then
if [ `ping 10.10.114.116 -c 1 -w 5 | grep 100%  | wc -l` -ge 1 ];then
        REMOTE_HOST="monitor.whaley.cn"
else
        REMOTE_HOST="10.10.114.116"
fi

echo $REMOTE_HOST >> $INIT_LOG_FILE

rgecho(){
	echo -e "\033[31m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}

ggecho(){
	echo -e "\033[32m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}
gecho(){
        echo -e "\033[45;37m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}

recho(){
        echo -e "\033[41;37m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}

pecho(){
	echo -e "\033[35m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}

becho(){
	echo -e "\033[34m $1 \033[0m" && echo $1 >> $INIT_LOG_FILE
}

default_init(){
becho "----------------------------------------------------------------------------------------------------"
pecho "欢迎使用该初始化脚本，如果您在使用中遇到任何问题或建议请及时告诉我！！"
becho "----------------------------------------------------------------------------------------------------"
gecho "开始进行初始化。。。。。。"
[[ -f /usr/share/.init.log ]] && rgecho "该机器已经初始化过!" && exit 0;

if [ `ping $HMS_IP -c 1 -w 5 | grep 100%  | wc -l` -eq 0 ];then
        echo '10.10.114.116     yumrepos.moretv.com.cn' >> /etc/hosts
else
	HMS_IP="123.59.77.3"
fi

echo $HMS_IP >> $INIT_LOG_FILE

gecho "wget "http://${REMOTE_HOST}/whaley_tools/moretv.repo" -P /etc/yum.repos.d/"
wget "http://${REMOTE_HOST}/whaley_tools/moretv.repo" -P /etc/yum.repos.d/ >> $INIT_LOG_FILE 2>&1

gecho "wget "http://${REMOTE_HOST}/whaley_tools/epel-release-latest-6.noarch.rpm""
wget "http://${REMOTE_HOST}/whaley_tools/epel-release-latest-6.noarch.rpm" >> $INIT_LOG_FILE 2>&1

gecho "rpm -ivh epel-release-latest-6.noarch.rpm"
rpm -ivh epel-release-latest-6.noarch.rpm >> $INIT_LOG_FILE 2>&1

#创建统一目录
gecho "create dir"
mkdir -p /data/upgrade_install/
mkdir -p /data/tools/
mkdir -p /data/bak/
mkdir -p /data/backup/
mkdir -p /data/webapps/
mkdir -p /data/logs/nginx
mkdir -p /data/logs/.history_video/
#chown -R moretv:moretv /data
chmod 755 /data
chmod 777 /data/logs/.history_video/

#安装基础软件包
gecho "install basic software"
yum install -y net-snmp iptraf vnstat ipmitool OpenIPMI nmap telnet yum-plugin-downloadonly systemtap psacct iftop jwhois bind-utils crontabs lua-devel openssl-devel pcre-devel zlib-devel nc unzip screen ftp lftp iotop golang crontabs MySQL-python ncftp m2crypto libaio numactl libev  perl-DBD-MySQL.x86_64 m2crypto python-requests crontabs lsof dmidecode 
yum groupinstall -y "Development Tools"
yum install -y jdk1.8.0_101.x86_64 --enablerepo=[moretv]
yum install -y percona-xtrabackup-24.x86_64 --enablerepo=[moretv]
yum install -y psutil --enablerepo=[moretv]
yum install -y puppet --enablerepo=[moretv]

#SSH免登陆
gecho "install ssh-key"
cd /root/
mkdir -p .ssh
cat >>/root/.ssh/authorized_keys <<"EOF"
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAx8injeUjuJHuZH3belnmG/zpLFAhl4qU7K0I/DMDX3+IAHuwNNqmzNZlYs6+faBmXw/wfonlTFSrbCZtjkDpxDpfH9SUWwpA7HKcjUQMWMLqwnRVVfAW7D6Gc9WoMoIm5MEKUD63Rftu8YTc3aLGXr5JTd1F73+kXxtpf3ckd+WfD4HVdtD94eMhx/e4+/ZhCdkAAkiFfIoXOCHxe5wQ0lfMPLTwYI2l6If2YRqSCiDo3XnvFnixTMCdOif4fpGqYPyGLGPo4rRTRulTP/Fe3pqEBCszDEvANRYy+JS0oMeF92w7XeZaJi50vMapssigPNTYdY+I8XmY2sUqMXywuQ== moretv@SSH-01
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAqxjfl7dKzhf7g1eCOzZ3N2VNxQ/HKf/YP0l4fKooVng1VGcBLkC8LX3H0IU72yeqzMctqmLD0dsICaHRtgLI+opIjOg9krHXTuiCt1uFlwa9/ZA/WUL/CaKQQpRk758toj+S1u9TKbe/OVJRjw/8qwfxebAk6bKqf+LcwPiFlq8WYL1EopvWhJxmTosIXtL/jBRFbclB78bYY5ZyHTaP5dXZFLVGIHQO1+vfas44kRKpxM5EusuE/WNl/18hxsd0jJx2y5hLEhXOmXcgCJpnK2BCB//EdSW251uw43tq9osRb9am43NhkPPDWq4KDbS4hsSLavDxb86jYDqhgdPx5w== root@zabbix_server_01
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCu+uaRIOfLaAdBnxEWrGvNimdNhPgCuOyoMtNQthWfu3+bWFigHMXY8XpKg3VeSL+OoBgojwIMNq2v1c+HmKw+4UPN4A1GnGgQw8WA2GPIf8o7gd1zL4sQSNBtD2LLYwNndKn3whx5xOmOUjYjovRwFIyiSKl9KieVLn3y817bAzZmJrkZ9vLxjP4p8CThITKiinzKHZdCbwuCrbs81FRw9tW38eOXiuE2U5W1SLEcL5++5fzND7uU+U/xMTTMssA28imwhNp+/YYZ/Zb3phiOxWUvsD1UjwDL7JuDCP7UsenYq/9yfpn2WSE6xVGtbuncjsNDUlqt38LhFP+Xjg97
EOF

chmod 700 /root/.ssh/
chmod 600 /root/.ssh/authorized_keys

useradd moretv
chown -R moretv:moretv /data
cd /home/moretv/
mkdir -p .ssh
cat >> /home/moretv/.ssh/authorized_keys <<"EOF"
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAx8injeUjuJHuZH3belnmG/zpLFAhl4qU7K0I/DMDX3+IAHuwNNqmzNZlYs6+faBmXw/wfonlTFSrbCZtjkDpxDpfH9SUWwpA7HKcjUQMWMLqwnRVVfAW7D6Gc9WoMoIm5MEKUD63Rftu8YTc3aLGXr5JTd1F73+kXxtpf3ckd+WfD4HVdtD94eMhx/e4+/ZhCdkAAkiFfIoXOCHxe5wQ0lfMPLTwYI2l6If2YRqSCiDo3XnvFnixTMCdOif4fpGqYPyGLGPo4rRTRulTP/Fe3pqEBCszDEvANRYy+JS0oMeF92w7XeZaJi50vMapssigPNTYdY+I8XmY2sUqMXywuQ== moretv@SSH-01
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCx+0VC0ZB0Bwov49fRP41zF6IOaF+ltZ3OKlXn8EpH75qy3NZ8mysUAecM/58YhvU0SR7jckq3XH/eagtV6rn57zeoPBjzFhZUNz3DoD7kBB0IvFjzEaJoBI3L6kHTE3az0MGg6W+bzNyK5cgw/I3brtbiTk/3QBGD19fmU7wWMxOMK4BDWGOPI8iz466PVUlU65HnaaAJhCuwcWfL4YJp/RaEZwmjXs58ec0GgMs7Z6pmfVtC4pffbxav8j2CayQ7fdQGkRH3bOv+Wu4gvcE//sRsHhPtw73wsz0gcsPZAeyjoFThqJg3HF0yS1yhvnCBF3SM9LaxJ6r2DCpfXaxB
EOF

chmod 700 /home/moretv/.ssh/
chmod 600 /home/moretv/.ssh/authorized_keys
chown moretv:moretv /home/moretv/.ssh/ -R

useradd readonly

mkdir -p /home/readonly/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfDR8pGeajsc+pTHc88fg2yWfpyugaPgrJ7FolfIunPdArklcUvw/9hRM+L99dy4a2a5a1ZYjPUHGD5+40aytQJR8ZabiEjQhesXBCPGKc5nEPgZtRoGl20br7dtKcIK7B8UwewHXy/3Kb8UlQ4J6CreQsdEN4PSZJGfSuUalDv/7+T6LvaT0jnQVZmG7IrsS4qX2Pd2AyI0bg2AfYpaXBTU7wC9peX5DB8wMjmHNK/DNOIwJl1pz/x+VkiKeyeaLFvgbCgrotM32lQ6MO+PZFEisFjEyQ5+CdatqlrB2/SyHHECsfBPD0IKVeFITCSeJ0eGUJ/KNuCkSJon9kfUIz' >> /home/readonly/.ssh/authorized_keys
chmod -R 700 /home/readonly/.ssh
chown -R readonly:readonly /home/readonly/.ssh/


gecho "change sshd_config"
sed -i -e 's/#RSAAuthentication\ yes/RSAAuthentication\ yes/' /etc/ssh/sshd_config
sed -i -e 's/#PubkeyAuthentication\ yes/PubkeyAuthentication\ yes/' /etc/ssh/sshd_config
sed -i -e 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config
sed -i -e 's/#UseDNS\ yes/UseDNS\ no/' /etc/ssh/sshd_config
sed -i -e '/X11Forwarding yes/s/yes/no/' /etc/ssh/sshd_config

service sshd restart

#关闭selinux
gecho "disable selinux"
sed -i -e '/SELINUX=enforcing/s/SELINUX=enforcing/SELINUX=disabled/' /etc/sysconfig/selinux
setenforce 0

#关闭不必要服务
gecho "off unnecessary service"
/sbin/chkconfig --level 0123456 auditd off
/sbin/chkconfig --level 0123456 ip6tables off
/sbin/chkconfig --level 0123456 iptables off
/sbin/chkconfig --level 0123456 kdump off
/sbin/chkconfig --level 0123456 lvm2-monitor off
/sbin/chkconfig --level 0123456 mdmonitor off
/sbin/chkconfig --level 0123456 restorecond off
/sbin/chkconfig --level 0123456 udev-post off
/sbin/chkconfig --level 0123456 psacct on
/sbin/chkconfig --level 0123456 ntpd off
/sbin/chkconfig --level 0123456 postfix off
/etc/init.d/iptables stop
/etc/init.d/ntpd stop

#设置时间同步服务器
gecho "set ntpdate"
cat >> /var/spool/cron/root << "EOF"
*/30 * * * * /usr/sbin/ntpdate ntp.whaley.cn > /dev/null 2>&1
EOF

cat >> /etc/hosts << "EOF"
10.10.167.158   ntp.whaley.cn
EOF

#修改文件限制
gecho "set ulimit"
cat >> /etc/security/limits.conf << "EOF"
*    -     nofile    1000000
EOF

cat >> /etc/security/limits.d/90-nproc.conf << "EOF"
*    soft     nproc    65535
EOF

#设置通用内核参数
gecho "set kernel parameter"
if ! grep "UCLOUD_INIT_KERNEL" /etc/sysctl.conf > /dev/null 2>&1;then
cat > /etc/sysctl.conf << "EOF"
# Kernel sysctl configuration file for Red Hat Linux
# UCLOUD_INIT_KERNEL
net.ipv4.ip_forward = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
kernel.sysrq = 0
kernel.core_uses_pid = 1
net.ipv4.tcp_syncookies = 1
#net.bridge.bridge-nf-call-ip6tables = 0
#net.bridge.bridge-nf-call-iptables = 0
#net.bridge.bridge-nf-call-arptables = 0
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 1025 65000
net.ipv4.tcp_max_syn_backlog = 20480
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_tw_buckets = 300000
net.ipv4.tcp_timestamps = 0
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.wmem_max = 16777216
net.core.rmem_max = 16777216
net.ipv4.tcp_rmem = 10240 87380 16777216
net.ipv4.tcp_wmem = 10240 87380 16777216
net.core.netdev_max_backlog = 50000
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_max_orphans = 3276800
net.core.somaxconn = 3276800
vm.swappiness = 10
fs.file-max = 1000000
fs.inotify.max_user_watches = 10000000
EOF
sysctl -p /etc/sysctl.conf
fi
#disable ctrl alt del=====================================================Begin
sed -i -e '/exec/s/exec/#exec/' /etc/init/control-alt-delete.conf

#Changing cron job of sysstat=============================================Begin
sed -i '/*\/10/s/*\/10/*/' /etc/cron.d/sysstat

#Changing search domain===================================================Begin
sed -i -e '/localhost.localdomain/s/localdomain/idc.moretv.com.cn/' /etc/sysconfig/network

#Disable IPv6=============================================================Begin
sed -i -e '/NETWORKING=yes/aNETWORKING_IPV6=no' /etc/sysconfig/network
sed -i -e '/NETWORKING=yes/aIPV6INIT=no' /etc/sysconfig/network
cat > /etc/modprobe.d/disable_ipv6.conf << "EOF"
install ipv6 /bin/true
EOF

# Set history
## echo "history command config..."
gecho "set hostory"
if ! grep "HISTTIMEFORMAT" /etc/profile >/dev/null 2>&1;then
cat >> /etc/profile << "EOF"
USER_IP=$(who -u am i 2>/dev/null | awk '{print $NF}' |sed -e 's/[()]//g')
HISTDIR=/usr/share/.history
if [ -z $USER_IP ];then
USER_IP=`hostname`
fi
if [ ! -d $HISTDIR ];then
mkdir -p $HISTDIR
chmod 777 $HISTDIR
fi
if [ ! -d $HISTDIR/${LOGNAME} ];then
mkdir -p $HISTDIR/${LOGNAME}
chmod 300 $HISTDIR/${LOGNAME}
fi
export HISTSIZE=4000
DT=$(date +%Y%m%d_%H%M%S)
export HISTFILE="$HISTDIR/${LOGNAME}/$USER_IP.history.$DT"
export HISTTIMEFORMAT="[%Y.%m.%d %H.%M.%S]"
chmod 600 $HISTDIR/${LOGNAME}/*.history* 2>/dev/null
ulimit -c unlimited

EOF
fi

#禁止yum升级系统内核
echo "exclude=kernel*" >> /etc/yum.conf

#安装python的ez_setup.py
gecho "install ez_setup"
cd /tmp/
wget "http://${REMOTE_HOST}/whaley_tools/ez_setup.py"
if [ `ping monitor.whaley.cn -c 1 -w 1 | grep 100%  | wc -l` -ge 1 ];then
	recho "访问外网失败－－！python的easy_install安装失败!"
else
	python ez_setup.py
fi


#设置puppet
gecho "set puppet"
echo '10.10.96.33 moretv-puppet01' >> /etc/hosts
echo '    server = moretv-puppet01' >> /etc/puppet/puppet.conf
puppet agent -t

#Install puppet===========================================================END
echo "install zabbix"
cd /tmp/
wget "http://${REMOTE_HOST}/whaley_tools/zabbix_agent_whaley.tar.gz"

tar zxf zabbix_agent_whaley.tar.gz

cd zabbix_agent
rpm -ihv zabbix-agent-3.2.3-1.el6.x86_64.rpm --nodeps --force > /dev/null 2>&1
sleep 3

if [ `id zabbix | wc -l` -lt 1 ];then
useradd zabbix -s /sbin/nologin
fi

mv -f zabbix_agentd.conf /etc/zabbix/zabbix_agentd.conf
cp -r scripts/ /etc/zabbix/
mv -f my.cnf-for_zabbix /etc/zabbix/my.cnf
mv -f userparameter_mysql.conf /etc/zabbix/zabbix_agentd.d/

chmod -R u+x /etc/zabbix/scripts/

if [ ! -d /var/log/zabbix ];then
        mkdir -p /var/log/zabbix
        chown -R zabbix.zabbix /var/log/zabbix/
fi

if [ ! -d /var/run/zabbix ];then
        mkdir -p /var/run/zabbix
        chown -R zabbix.zabbix /var/run/zabbix/
fi

if [[ "$VIRTUAL_ROUTE" = "1" ]];then
	sed -i -e '/^Server=/ s+Server=.*+Server=10.10.154.153+g' /etc/zabbix/zabbix_agentd.conf
	sed -i -e '/^ServerActive=/ s+ServerActive=.*+ServerActive=10.10.154.153:10051+g' /etc/zabbix/zabbix_agentd.conf
fi

ps -ef | grep zabbix_agentd | grep -v grep | while read u p o
do
kill -9 $p
done

sleep 3

/etc/init.d/zabbix-agent start

RESULT=`ps -ef | grep -w zabbix_agentd.conf | grep -v grep | wc -l`

if [ $RESULT -ge 1 ];then
        echo "zabbix_agent installed"
        rm -rf zabbix_agent
else
        /etc/init.d/zabbix-agent restart
fi
/sbin/chkconfig --add zabbix-agent
/sbin/chkconfig zabbix-agent on

gecho "install agent"
mkdir -p /root/tools/
cd /root/tools/
wget http://${REMOTE_HOST}/whaley_tools/agent_install.zip
unzip agent_install.zip
cd agent
./agent install

sed -i 's+10.10.114.116+'$HMS_IP'+g' /root/tools/agent/config/config.ini
/etc/init.d/agent start
sleep 10
/etc/init.d/agent restart
/sbin/chkconfig --add agent
/sbin/chkconfig agent on
#install agent====================================End
touch /usr/share/.init.log
echo `date +%F` > /usr/share/.init.log
/usr/bin/chattr +i /usr/share/.init.log

/etc/init.d/rsyslog restart
}

change_hostname(){
	HOSTNAME=$1	
	gecho "change hostname $HOSTNAME"
	if [ ! -z $HOSTNAME ];then
		`which hostname` $HOSTNAME
		`which sed` -i 's+HOSTNAME=.*+HOSTNAME='$HOSTNAME'+g' /etc/sysconfig/network
        fi
	if [ -f "/etc/init.d/zabbix-agent" ];then
		/etc/init.d/zabbix-agent restart
	fi
}

gecho(){
	echo -e "\033[45;37m $1 \033[0m"
}

recho(){
	echo -e "\033[41;37m $1 \033[0m"
}

print_install_info(){
	gecho " 开始安装$1!!!!!"
	sleep 1
}

yum_install(){
	gecho "install $1"
	yum install --enablerepo=moretv -y $1
}

check_process(){
	if  [ `rpm -qa | grep $1 | wc -l` -ge $2 ] && [ ! -z "`whereis $1  | cut -d: -f2`" ];then
        	recho "$1已经安装,请勿重复安装,请使用rpm -qa | grep $1确认。"
         	return 1
	fi
}


system_install(){
	for var in $@
	do
		case $var in
		nginx)
			#yum install -y  -enablerepo=moretv
			print_install_info $var
			check_process $var 1
			if [ $? == 1 ];then
                	continue
                	else
			yum_install Moretv_nginx
			yum install -y memcached
			/usr/bin/memcached -p 11211 -u root -m 1024 -c 1024 -d
			fi
			;;
		php|php5)
			print_install_info $var
			check_process $var 1
                        if [ $? == 1 ];then
                        continue
                        else
			yum_install Moretv_php-5.6.21 Moretv_libmemcached Moretv_memcached phpredis
			fi
			;;
		
		tomcat)
			print_install_info $var
			check_process $var 1
                        if [ $? == 1 ];then
                        continue
                        else
			yum_install Moretv_tomcat
			fi
			;;
		php7)
			print_install_info $var
                        check_process $var 1
                        if [ $? == 1 ];then
                        continue
                        else
			yum_install Moretv_php-7-0.5 Moretv_libmemcached Moretv_memcached phpredis
                        fi
			;;
		"mysql5.5"|"Moretv_mysql5.5")
			print_install_info $var
#			check_process $var 2
                        if [ $? == 1 ];then
                        continue
                        else
			wget http://$REMOTE_HOST/whaley_tools/rpm/Moretv_mysql-5.5.28.tar.gz -P /data/tools
			cd /data/tools
			tar -zxvf Moretv_mysql-5.5.28.tar.gz && cd Moretv_mysql-5.5.28 && sh install_mysql.sh
			cd /
			rm -f /data/tools/Moretv_mysql-5.5.28.tar.gz
			rm -rf /data/tools/Moretv_mysql-5.5.28
			fi
			;;

                "mysql5.7"|"Moretv_mysql5.7")
                        print_install_info $var
#                       check_process $var 2
                        if [ $? == 1 ];then
                        continue
                        else
                        wget http://$REMOTE_HOST/whaley_tools/rpm/Moretv_mysql-5.7.16.tar.gz -P /data/tools
                        cd /data/tools
                        tar -zxvf Moretv_mysql-5.7.16.tar.gz && cd Moretv_mysql-5.7.16 && sh install_mysql.sh
                        cd /
                        rm -f /data/tools/Moretv_mysql-5.7.16.tar.gz
                        rm -rf /data/tools/Moretv_mysql-5.7.16
                        fi
                        ;;
		nodejs|nodejs5)
			print_install_info $var
			check_process $var 1
                        if [ $? == 1 ];then
                        continue
                        else
			yum_install Moretv_nodejs5.2
			fi
			;;
		redis)
			print_install_info $var
                        check_process $var 1
                        if [ $? == 1 ];then
                        continue
                        else
			yum_install Moretv_redis
                        fi
			;;
		*)
			recho "请使用\"yum install\"安装$var"
			;;
	esac
	done
}

show_yumrepo(){
	if ! yum list | grep -w "moretv" > /dev/null 2>&1;then
		echo -e "\033[31m \033[1m \033[5m 还没安装moretv的源，请先安装!!! \033[0m"
		exit
	else
	echo -e "\033[32m 可安装的软件包有以下:"
	yum list | grep -w "moretv" | awk '{print $1}'	
	echo -e "\033[0m"
	fi
}

usage_info(){
	        echo "Usage:$0 -i -n [-V] hostname -a [install soft's name]."
                echo "参数说明:"
		echo "-l:显示自订制的moretv源可安装的软件包。"
                echo "-i:只做初始化安装。"
		echo "-V:当云主机使用虚拟路由器时使用该参数，可使zabbix不探测虚拟路由，使用内网地址。"
                echo "-n:指定要修改的主机名。"
                echo "-a:选择要安装的软件包，多个软件包需要用双引号括起来，如\"$0 -a \"nginx mysql php\"\""
                echo -e "\033[43;31m!!!!!!友情提示!!!!!!\033[0m"
                echo -e "\033[43;31m*安装多个软件包一定记着用引号哟!\033[0m"
                echo -e "\033[43;31m*可安装软件包可以下载安装自订制的yum源查看.\033[0m"
                echo -e "\033[43;31m*下载地址\"http://monitor.whaley.cn/whaley_tools/moretv.repo\".\033[0m"
                echo -e "\033[43;31m*然后你懂得，自己查一下吧！！\033[0m"
}

[[ $# -eq 0 ]] && usage_info

while getopts "Vlih:n:a:" opt;do
    case $opt in
	l)	SHOW_REPOLIST=1;;
		#show_yumrepo;;
	V)	VIRTUAL_ROUTE=1;;
	n) 	HOST_NAME=$OPTARG
        	;;
	i)  DEFAULT_INIT=1
                ;;
	a)
		INSTALL_SOFT=1
		SOFTNAME=$OPTARG	
#		ggecho "你想安装<<$OPTARG>>?"
#		system_install $OPTARG
		;;
        h|*)	usage_info 
                exit 0 ;;
    esac
done

if [ ! -z $HOST_NAME ];then
        change_hostname $HOST_NAME
fi

if [ $DEFAULT_INIT = 1 ];then
	default_init
fi

if [ $INSTALL_SOFT = 1 ];then
	ggecho "你想安装<<$SOFTNAME>>?"
        system_install $SOFTNAME
fi

if [ $SHOW_REPOLIST = 1 ];then
	show_yumrepo
fi

