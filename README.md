### ISOFC for ArmBian

SOFT for Arabian: The system of secure and authorized exchange of files between the usb device and Samba server

Designed for use in educational organization and enterprises where used and irect mount and use USB drives is prohibit prohibited because of information security requirements.

For autintication of USB drive isofc use a hash file containing the serial number of the USB drive, user login and password

This product is a service that must be constantly running on a computer with access to the SAMBA server

Author: Klementyev Mikhail <jollheef@riseup.net>

Porting for armbian: Nicolskiy Anton <angeloffree@yandex.ru>

### Installing on deb based Linux OS

    $ sudo apt install git python3 python3-pip samba samba-common python-glade2 system-config-samba
    $ sudo service smbd restart
    $ sudo pip3 install pyudev time simplejson configparser
    $ git clone https://github.com/OlenEnkeli/isofc_armbian

    
### Installing on rpm based Linux OS

    $ sudo rpm install git python3 python3-pip samba samba-client samba-common
    $ sudo systemctl restart smb
    $ sudo pip3 install pyudev time simplejson configparser
    $ git clone https://github.com/OlenEnkeli/isofc_armbian

### Установка на arch based системах

    $ sudo pacman -S git python python-pip samba
    $ sudo systemctl restart smbd
    $ sudo pip3 install pyudev time simplejson configparser
    $ git clone https://github.com/OlenEnkeli/isofc_armbian
    

Don`t forget change configuration file and generate open and privacy RSA keys 

Net you will start ./isofc-service.py from cron or another way.