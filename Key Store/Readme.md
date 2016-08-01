1) Go to one of the nodes and install mysql

  sudo apt-get install mysql-server

Set the password to "qwerty" when prompted

2) Disable skip-networking in my.cnf (i.e: /etc/mysql/my.cnf)

3) Check value of bind-address in my.cnf, if it's set to 127.0.0.1, you can change it to 0.0.0.0 to allow access from all IPs or whatever ip that you want to connect from.

4) Login to mysql using "sudo mysql -u root -p" -- Type in qwerty for password

Copy and paste the following command:-

GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'
    IDENTIFIED BY 'qwerty'
    WITH GRANT OPTION;
    
Then this :- 
FLUSH PRIVILEGES;`


5) The restart the mysql service using

sudo service mysql restart
