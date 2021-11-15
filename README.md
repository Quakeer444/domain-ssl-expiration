This script created for check domain expiration and ssl expiration



To take on the zabbix you need to add the script in folder "externalscripts"
and use "External Checks".
Example:

type - 'External checks'
item key - "ssh-domain-expiration.py[example.com,domain]"   # check domain expiration
item key - "ssh-domain-expiration.py[example.com,ssl,443]"  # check ssl expiration

______________________
This script can be used in the other monitoring system or just to use terminal 
linux