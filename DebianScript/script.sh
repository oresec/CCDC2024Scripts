#!/bin/bash
#Check if sudo
if [ $UID != 0 ]; then
    echo " use sudo and try again... "
    exit
fi
#Clean packages
echo "Cleaning packages"
apt-get update
apt-get autoremove -y
apt-get autoclean -y
apt-get update

read -p "Do you want to update packages? [y,n]" runupdates
if [ $runupdates == "y" ]
	then
		echo "UPDATING PACKAGES"
		apt-get upgrade -y
fi

#Automatic updates
apt-get install -y unattended-upgrades
dpkg-reconfigure unattended-upgrades

#pam dependencies
apt-get install -y libpam-cracklib


cp ./common-password /etc/pam.d/common-password
# Common-auth sets lockout policy, currently broken in this script
# Newer versions of debian/ubuntu use pam_faillock.so while older ones use pam_tally2.so
# Just do this part by hand
#cp ./common-auth /etc/pam.d/common-auth
cp ./login.defs /etc/
apt-get install -y gufw
ufw enable
sysctl -n net.ipv4.tcp_syncookies
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | tee -a /etc/sysctl.conf
echo 0 | tee /proc/sys/net/ipv4/ip_forward
# Do not uncomment, caused problems on newer versions of Ubuntu
# echo "nospoof on" |  tee -a /etc/host.conf

locate *.mp3 *.txt *.mp4 *.wav *.avi | grep ^/home
# delete bad packages
for i in arp-scan braa dirb hashcat dnswalk faraday-server donna spampd ophcrack tmux snap pinta knocker nbtscan pompem crunch netcat lynis xprobe john zenmap binwalk sl john-data medusa hydra dsniff netcat-openbsd netcat-traditional traceroute telnet wireshark aircrack-ng pyrit zeitgeist nmap yersinia deluge httpry p0f dos2unix kismet transmission sendmail tightvncserver finger xinetd cain minetest tor moon-buggy dovecot rsh-server aisleriot hping3 freeciv darkstat nis sqlmap libaa-bin gdb skipfish extremetuxracer ninvaders freesweep nsnake bsdgames
do
    #faster than apt purge for every package
    if dpkg-query -W $i; then
        sudo apt purge -y $i 
    fi

done
updatedb
# core dumps and max logins
bash -c 'echo "* hard core 0" >> /etc/security/limits.conf'
bash -c 'echo "* hard maxlogins 10" >> /etc/security/limits.conf'

# systemctl disable snmpd
# systemctl disable squid
# systemctl disable smbd 
# systemctl disable dovecot
# systemctl disable slapd
# systemctl disable isc-dhcp-server 
# systemctl disable isc-dhcp-server6
# systemctl disable cups 
# systemctl disable avahi-daemon 
# systemctl disable autofs

# Firefox policy config - see user.js
cp ./user.js /etc/firefox/user.js
cp ./firefox-esr.js /etc/firefox-esr/firefox-esr.js # <- debian specific

#Kernel security
bash -c "echo 'kernel.dmesg_restrict=1' > /etc/sysctl.d/50-dmesg-restrict.conf"
bash -c"echo 'kernel.kptr_restrict=1' > /etc/sysctl.d/50-kptr-restrict.conf"
bash -c "echo 'kernel.exec-shield=2' > /etc/sysctl.d/50-exec-shield.conf"
bash -c "echo 'kernel.randomize_va_space=2' > /etc/sysctl.d/50-rand-va-space.conf"
#bash -c "apt-get --purge -y remove ubuntu-desktop firefox "
#bash -c "passwd -l $USER"
#bash -c "passwd -l root"
#bash -c "/sbin/shutdown now"
#system logging
systemctl enable rsyslog
systemctl start rsyslog


#### Add/remove users based on users.txt ####

userlines=$(wc -l users.txt | awk '{print $1}')
adminlines=$(wc -l admins.txt | awk '{print $1}')
### Remove bad packages

if [ $userlines -lt 4 ] || [ $adminlines -lt 2 ];then
    echo "You probably didn't fill in the users.txt and admins.txt files, quitting"
    exit 1
fi

# Function to add a user with a clear-text password
add_user_with_password() {
    local username=$(echo -E ${1} | xargs)
    local password="BlasterR0x123!"
    sudo useradd -m $username
    echo -e "$password\n$password" | sudo passwd $username
    echo "Added user $username with password $password"
}

# Function to delete a user
delete_user() {
    local username="$1"
    sudo deluser "$username" &>/dev/null
    echo "Deleted user $username"
}

change_password() {
    local username="${1}"
    local password="${2}"
    echo -e "$password\n$password" | sudo passwd $username
    echo -e "Changed $username's password"
}

# Main script starts here
while read line; do
    username=$(echo "$line" | awk '{print $1}')
    userstrip=$(echo "$username" | xargs) #Have to remove whitespace
    password="BlasterR0x123!"
    #If user already exists, change password
    if id "$userstrip" &>/dev/null; then
        change_password "$userstrip" "$password" 
    else
        add_user_with_password "$userstrip"
    fi
done < users.txt

# Limit to users with uid > 1000
# Prevents us from deleting service accounts (uid < 1000)
# Should also check for users with uid=0 (root equivalent)
current_users=$(awk -F: '($3>=1000)&&($1!="nobody"){print $1}' /etc/passwd)
for user in $current_users; do
    if ! grep -q "$user" users.txt; then # user file is called users.txt
        delete_user "$user"
    fi
done

### Remove / promote administrators based on admins.txt file ###
# Function to check if a user is an administrator
is_admin() {
    local user="$1"
    if sudo getent group sudo | grep -q "$user"; then
        return 0  # User is in the sudo group
    elif sudo getent group admin | grep -q "$user"; then
        return 0  # User is in the admin group
    elif sudo grep -q "$user" /etc/sudoers; then
        return 0  # User is explicitly listed in sudoers
    else
        return 1  # User is not an admin
    fi
}

# Function to promote a user to admin
promote_to_admin() {
    local user="$1"
    sudo usermod -aG sudo "$user"
    echo "Promoted $user to admin"
}

# Function to demote a user from admin
demote_from_admin() {
    local user="$1"
    sudo deluser "$user" sudo
    sudo deluser "$user" admin
    echo "Removed $user from admin"
}

# Main script starts here
while IFS= read -r user; do
    if id "$user" &>/dev/null && is_admin "$user"; then
        echo "$user is already an admin"
    else
        promote_to_admin "$user"
    fi
    
done < admins.txt

# Check for users that are admin but shouldn't be
current_admins=$(sudo getent group sudo | awk -F: '{print $4} ' | tr "," " ")
for admin in $current_admins; do
    if ! grep -q "$admin" admins.txt; then # admin file is called admins.txt
        demote_from_admin "$admin"
    fi
done


### Lock root user ###
change_password "root" 'BlasterR0x123!'
sudo passwd -l root
sudo usermod -g 0 root

#### Set permissions of important files ####

sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow

#permissions
chmod 755 /bin/nano
chmod 644 /bin/bzip2
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
chmod 644 /etc/passwd 
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chmod 644 /etc/hosts.deny 
chmod 644 /etc/hosts.allow 
chmod 644 /etc/passwd /etc/group /etc/shells /etc/login.defs /etc/securetty /etc/hosts.deny /etc/hosts.allow
chown -R root /etc/*
chmod 0000 /etc/shadow /etc/gshadow
chmod 600 /etc/sysctl.conf
chmod 755 /etc
chmod 755 /bin/su
chmod 755 /bin/bash
chmod u+s /bin/sudo
chmod u+s /bin/su
chmod u+s /sbin/unix_chkpwd
chmod 755 /sbin/ifconfig
chmod 666 /dev/null /dev/tty /dev/console
chmod 600 /boot/grub/grub.cfg
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
chmod 0700 /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* 

## Set MOTD ##
#/etc/issue and /etc/issue.net stig
bash -c 'echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." > /etc/issue'
bash -c 'echo "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." > /etc/issue.net'

# Set user password age requirements
y=$(awk -F':' '{ print $1}' /etc/passwd)
	declare -a y
	for x in ${y[@]}; do
		 #x="administrator"
		 chage -m 7 -M 90 -W 14 $x
	done
