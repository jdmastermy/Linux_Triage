#!/bin/bash

#INITIAL HOUSEKEEPING 
ScriptStart=$(date +%s)
LRbuildname="Standard"
ScriptName=`basename "$0"`
ScriptDir=$(pwd) #Getting directory from where the script is running

runningfromexternal="no"
cname=$(hostname -s)
ts=$(date +%Y%m%d_%H%M)
computername=$cname\_$ts
mkdir -p $computername
printf "***** All commands run and (if applicable) any error messages *****\n" >> "$computername/$computername""_Processing_Details.txt"
printf "OS Type: nix\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Computername: $cname\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Time stamp: $ts\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Live Response Collection version: $LRbuildname\n" >> "$computername/$computername""_Processing_Details.txt"
printf "Live Response Collection script run: $ScriptName\n\n" >> "$computername/$computername""_Processing_Details.txt"
printf "mkdir -p $computername\n" >> "$computername/$computername""_Processing_Details.txt"


# Directory Creation

echo "***** Now running directory creation process *****"

printf "Comamnd Run: mkdir -p $computername/ForensicImages/Memory\n"
printf "Comamnd Run: mkdir -p $computername/ForensicImages/Memory\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/ForensicImages/Memory >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/ForensicImages/DiskImage\n"
printf "Command Run: mkdir -p $computername/ForensicImages/DiskImage\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/ForensicImages/DiskImage >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/BasicInfo\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/BasicInfo\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/BasicInfo >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/UserInfo\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/UserInfo\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/UserInfo >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/NetworkInfo\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/NetworkInfo\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/NetworkInfo >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/PersistenceMechanisms\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/PersistenceMechanisms\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/PersistenceEntries >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/Logs\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/Logs\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/Logs >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/Logs/var\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/Logs/var\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/Logs/var >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

printf "Command Run: mkdir -p $computername/LiveResponseData/PersistenceEntries/cron\n"
printf "Command Run: mkdir -p $computername/LiveResponseData/PersistenceEntries/cron\n" >> "$computername/$computername""_Processing_Details.txt"
mkdir -p $computername/LiveResponseData/PersistenceEntries/cron >> "$computername/$computername""_Processing_Details.txt" 2>&1
printf "\n\n" >> "$computername/$computername""_Processing_Details.txt"

echo "***** Completed running directory creation *****"


# File Event Timeline Generation
echo -e "Mtime\t Ctime\t Atime\t Permission\t User\t Group\t Size\t File" >> $computername/$cname-FileEvent_Timeline_Root.log
find / -xdev -type d -printf "%TY-%Tm-%Td %TH:%TM:%TS\t %CY-%Cm-%Cd %CH:%CM:%CS\t %AY-%Am-%Ad %AH:%AM:%AS\t %M\t %u\t %g\t %s\t %p \n" -o -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS\t %CY-%Cm-%Cd %CH:%CM:%CS\t %AY-%Am-%Ad %AH:%AM:%AS\t %M\t %u\t %g\t %s\t %p \n" >> $computername/$cname-FileEvent_Timeline_Root.log

# LVM Environment, find command needs to be able to search on all volumes so have to generate list of /dev/mapper
mount | grep "/dev/mapper" | grep -o ' /.* ' | awk -F" " '{ print $1 }' > $computername/$cname-Device_Mapper_List.log

# Generate File Timeline for OS with LVM Setup
echo -e "Mtime\t Ctime\t Atime\t Permission\t User\t Group\t Size\t File" >> $computername/$cname-FileEvent_Timeline_LVM.log

for i in `cat $computername/$cname-Device_Mapper_List.log`; do
	find $i -xdev -type d -printf "%TY-%Tm-%Td %TH:%TM:%TS\t %CY-%Cm-%Cd %CH:%CM:%CS\t %AY-%Am-%Ad %AH:%AM:%AS\t %M\t %u\t %g\t %s\t %p \n" -o -type f -printf "%TY-%Tm-%Td %TH:%TM:%TS\t %CY-%Cm-%Cd %CH:%CM:%CS\t %AY-%Am-%Ad %AH:%AM:%AS\t %M\t %u\t %g\t %s\t %p \n" >> $computername/$cname-FileEvent_Timeline_LVM.log
done


# EXPORT PATH
# export PATH=/usr/kerberos/bin:/usr/local/bin:/usr/bin:/bin:/usr/X11R6/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/games:/usr/local/games:/snap/bin

# LOGS
find /var/log -type f -name *.log* -exec cp -p '{}' $computername/LiveResponseData/Logs/var \;
cp -p /var/log/secure $computername/LiveResponseData/Logs/var


# PERSISTANCE ENTRIES
cp -p -r /etc/cron* $computername/LiveResponseData/PersistenceEntries/cron
cp -p /etc/rc.local $computername/LiveResponseData/PersistenceEntries
cp -p /etc/rc.d/rc.local $computername/LiveResponseData/PersistenceEntries
service --status-all | grep + >> $computername/LiveResponseData/PersistenceEntries/Running_services.txt
echo "service --status-all | grep +"
chkconfig --list >> $computername/LiveResponseData/PersistenceEntries/SystemV_Services.txt
echo "chkconfig --list" 
lsmod >> $computername/LiveResponseData/PersistenceEntries/Loaded_Module_List.txt
echo "lsmod"

systemctl list-unit-files --state=enabled >> $computername/LiveResponseData/PersistenceEntries/Systemctl_enabled.txt
systemctl | grep running >> $computername/LiveResponseData/PersistenceEntries/Systemctl_running.txt


# BASIC INFORMATION
date >> $computername/LiveResponseData/BasicInfo/date.txt
echo "date"
hostname >> $computername/LiveResponseData/BasicInfo/hostname.txt
echo "hostname"
who >> $computername/LiveResponseData/BasicInfo/Logged_In_Users.txt
echo "who"
ps aux --forest >> $computername/LiveResponseData/BasicInfo/List_of_Running_Processes.txt
echo "ps aux --forest"
pstree -ah >> $computername/LiveResponseData/BasicInfo/Process_tree_and_arguments.txt
echo "pstree -ah"
mount >> $computername/LiveResponseData/BasicInfo/Mounted_items.txt
echo "mount"
diskutil list >> $computername/LiveResponseData/BasicInfo/Disk_utility.txt
echo "diskutil"
df -h >> $computername/LiveResponseData/BasicInfo/FileSystem_Usage.txt
echo "df -h"
kextstat -l >> $computername/LiveResponseData/BasicInfo/Loaded_Kernel_Extensions.txt
echo "kextstat -l"
uptime >> $computername/LiveResponseData/BasicInfo/System_uptime.txt
echo "uptime"
uname -a >> $computername/LiveResponseData/BasicInfo/System_environment.txt
echo "uname -a"
printenv >> $computername/LiveResponseData/BasicInfo/System_environment_detailed.txt
echo "prinenv"
cat /proc/version >> $computername/LiveResponseData/BasicInfo/OS_kernel_version.txt
echo "cat /proc/version"
top -n 1 -b >> $computername/LiveResponseData/BasicInfo/Process_memory_usage.txt
echo "top -n 1 -b"
dmesg >> $computername/LiveResponseData/BasicInfo/Dmesg.txt
echo "dmesg"
cat /etc/fstab >> $computername/LiveResponseData/BasicInfo/fstab.txt
echo "cat /etc/fstab"
last >> $computername/LiveResponseData/BasicInfo/Last_logins.txt
echo "last"


# USER INFORMATION
cat /etc/passwd >> $computername/LiveResponseData/UserInfo/passwd.txt
echo "cat /etc/passwd"
cat /etc/group >> $computername/LiveResponseData/UserInfo/group.txt
echo "cat /etc/group"
lastlog >> $computername/LiveResponseData/UserInfo/Last_login_per_user.txt
echo "lastlog"
whoami >> $computername/LiveResponseData/BasicInfo/whoami.txt
echo "whoami"
logname >> $computername/LiveResponseData/BasicInfo/logname.txt
echo "logname"
id >> $computername/LiveResponseData/BasicInfo/id.txt
echo "id"
for i in `ls /home/`
do 
	cat /home/$i/.bash_history >> $computername/LiveResponseData/UserInfo/home-$i-bash_History.txt
	echo "cat $i bash_history"
done


# NETWORK INFO
netstat -anp >> $computername/LiveResponseData/NetworkInfo/netstat_current_connections.txt
echo "netstat"
ip addr >> $computername/LiveResponseData/NetworkInfo/network_ip_info.txt
echo "ip addr"
ip link | grep PROMISC >> $computername/LiveResponseData/NetworkInfo/PROMISC_adapter_check.txt
echo "PROMISC adapters"
ss >> $computername/LiveResponseData/NetworkInfo/socket_statistics.txt
echo "ss"
lsof -i -n -P>> $computername/LiveResponseData/NetworkInfo/lsof_network_connections.txt
echo "lsof -i -n -P"
netstat -rn >> $computername/LiveResponseData/NetworkInfo/Routing_table.txt
echo "netstat -rn"
arp -an >> $computername/LiveResponseData/NetworkInfo/ARP_table.txt
echo "arp -an"
ifconfig -a >> $computername/LiveResponseData/NetworkInfo/Network_interface_info.txt
echo "ifconfig -a"
cat /etc/hosts.allow >> $computername/LiveResponseData/NetworkInfo/Hosts_allow.txt
echo "cat /etc/hosts.allow"
cat /etc/hosts.deny >> $computername/LiveResponseData/NetworkInfo/Hosts_deny.txt
echo "cat /etc/hosts.deny"

# Docker Container Forensic
# https://docs.docker.com/engine/reference/commandline/ps/#formatting
# docker inspect -f "{{.Name}} {{.Path}} {{.Args}}" $(docker ps -a -q)
# docker ps -a --no-trunc
# docker ps --all
# STATUS
# docker ps --filter status=running
# docker ps --filter status=paused
# VOLUME
# docker ps --filter volume=remote-volume --format "table {{.ID}}\t{{.Mounts}}"
# docker ps --filter volume=/data --format "table {{.ID}}\t{{.Mounts}}"
# NETWORK
# docker run -d --net=net1 --name=test1 ubuntu top
# docker ps --filter network=net1
# docker network inspect --format "{{.ID}}" net1
# docker ps --filter network=8c0b4110ae930dbe26b258de9bc34a03f98056ed6f27f991d32919bfe401d7c5
# PUBLISH & EXPOSE
# docker ps --filter publish=1-65535/tcp
# docker ps --filter publish=1-65535/udp
# docker ps --filter expose=1-65535/tcp
# docker ps --filter expose=1-65535/udp
# FORMAT
# docker ps --format "{{.ID}}: {{.Command}}"
# Available options for --format - .ID | .Image | .Command | .CreatedAt | .RunningFor | .Ports | .Status | .Size | .Names | .Labels | .Label | .Mounts | .Networks


# PROCESSING DETAILS AND HASHES
echo OS Type: nix >> $computername/Processing_Details_and_Hashes.txt
echo Computername: $cname >> $computername/Processing_Details_and_Hashes.txt
echo Time stamp: $ts >> $computername/Processing_Details_and_Hashes.txt
echo >> $computername/Processing_Details_and_Hashes.txt
echo ==========MD5 HASHES========== >> $computername/Processing_Details_and_Hashes.txt
find $computername -type f \( ! -name Processing_Details_and_Hashes.txt \) -exec md5sum {} \; >> $computername/Processing_Details_and_Hashes.txt
echo >> $computername/Processing_Details_and_Hashes.txt
echo ==========SHA256 HASHES========== >> $computername/Processing_Details_and_Hashes.txt
find $computername -type f \( ! -name Processing_Details_and_Hashes.txt \) -exec shasum -a 256 {} \; >> $computername/Processing_Details_and_Hashes.txt
echo "Computing hashes of files"


# File Type Generation
find / -xdev -type f -exec file -p -F "|" '{}' \; > $computername/$cname-FileList_Ouput-Filetype_Root.log

for i in `cat $computername/$cname-Device_Mapper_List.log`; do
	find $i -xdev -type f -exec file -p -F "|" '{}' \; >> $computername/$cname-FileList_Ouput-Filetype_LVM.log
done


exit

# Update
# 20190509 - file command is executed with -p option to preserve the access timestamp (up to second)
# 20190515
# cp command is executed with -p option to preserve timestamp of file being copied
# /var/log/secure is copied for RHEL platform as security related system log
# /var/log/*.log* is copied instead of /var/log/*.log as some of logs are named with additional extension in file name
