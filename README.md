to be able to use this tool 

1. You need to configure pdu unit, by using the serial port and log in to the host by using localadmin/localadmin and change the password 
2. After that you need to enable the ipv4 by typing in CLI IPv4 enable and then apply network, which will activate the public Ip for the PDU.
3. Log in with the new IP address and using the localadmin as user and the new password in any browser 
4. Navigate to the service 
5. activate SSH 
6. save 
7.apply, the system will reboot will not affect anything that power on the PDU will not affect any ongoing test
8. install the PDU_manger.exe
9. add a pdu name:
10.add the IP 
11. username :localadmin
12.password 
13. save , and you can edit remove any time 
14. select the required pdu and ssh to it 
15, you can control any power outlet you like 
16. you can write cli command in the GUI 
17. some off the command available 
 aaa - Configure Authentication and Accounting
         action - Create and manage actions
          alert - Acknowledge and export alerts
          apply - Apply changes to the system
      autoprobe - Create and manage AutoProbes
         backup - Backup settings and create restore point
          clock - Configure the system date and time
        contact - Modify the system contact information
        default - Configure the default time, date & temperature
         device - Manage a device
            dns - Configure DNS settings
          email - Create and manage email recipients
          event - Create and manage events
           exit - Terminate the CLI session
       firmware - Update the PowerAlert firmware
           help - Display available commands
           host - Modify the host name
           http - Configure HTTP settings
          https - Configure HTTPS settings
           ipv4 - Configure IPv4 settings
           ipv6 - Configure IPv6 settings
    ldap-server - Create and manage LDAP servers
            log - Display and configure logs
            man - Display information about the command
             no - Disable, remove or delete content
       password - Modify the login password
password-policy - Configure password policies
           quit - Terminate the CLI session
  radius-server - Create and manage RADIUS servers
         reboot - Reboot PowerAlert
        restore - Apply a previous configuration
           role - Create and manage roles
       schedule - Create and manage scheduled actions
            scp - Configure SCP settings
           sftp - Configure SFTP settings
           show - Display command details
            sms - Create and manage SMS recipients
           smtp - Configure SMTP settings
           snmp - Configure SNMP settings
    snmp-server - Create and manage SNMP servers
      snmp-user - Create and manage SNMP users
            ssh - Configure SSH settings
  syslog-server - Create and manage syslog servers
         telnet - Configure telnet settings
           user - Create and manage users
