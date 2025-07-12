![snort commands](<../Helpful Files/snort-101-commands.png>)

![snort rule breakdown](<../Helpful Files/snort-101-rule-breakdown.png>)

[List of file signatures](<https://en.wikipedia.org/wiki/List_of_file_signatures>)

***
# Task 1 - Introduction

Exercises for each task are located on the desktop: `/home/ubuntu/Desktop/Exercise-Files/`

***

# Task 2 - Writing IDS Rules (HTTP)
## Write a rule to detect all TCP packet **from or to** port 80.

The rule is as follows in local.rules: `alert tcp any 80 <> any any (msg:"TCP 80 Packet Found", sid:1000001; rev:1;)`  
To utilise the rule and inspect the given pcap-file, I'll use the following command inside the `TASK-2 (HTTP)` folder: `sudo snort -c local.rules -A full -l . -r mx-3.pcap`  

Breakdown:
- `sudo` as snort requires elevated rights by default. I am logged in as a regular user, and thus must use sudo.
- `snort -c local.rules` to specify the file with the rule-set that I want to use.  
- `-A full` to specify that I want the *full* alert mode to be used. This means that any alerts are added to the alert-file that exists, or will be generated, along with the full decoded header form the Packet.  
- `-l .` to specify that I want any generated logs in the same folder, as where the command is issued.  
- `-r mx-3.pcap` specifies that I want all of this, to be used with the `mx-3.pcap`-file that exists in the same directory.

### What is the number of detected packets from or to port 80?  

> 164  

### Investigate the log file: What is the destination address of packet 63?  

To find Packet 63: `sudo snort -r snort.log.{unix-timestamp} -n 63`  
`-n` specifies how many Packets to process before quitting.   
> `216.239.59.99`  

### What is the ACK number of packet 64?  

Again, utilising `-n` it's quite fast to find Packet 64 and extract the ACk number. 
> `0x2E6B5384`

### What is the SEQ number of packet 62?

`-n` could be used again. The previous question was regarding Packet 64, so simply looking 2 Packets prior, it's fast to find the SEQ.  
> `0x36C21E28`.

### What is the TTL of packet 65?

`-n` had to be used again, luckily the last questions are regarding the same Packet.  
> 128

### What is the source IP of Packet 65?

> `145.254.160.237`

### What is the Source port of Packet 65?
> `3372`

***
# Task 3 - Writing IDS Rules (FTP)
## Write a **single** rule to detect *all TCP port 21* traffic in the given pcap.

The rule is as follows in local.rules: `alert tcp any 21 <> any any (msg:"TCP 21 Packet Found"; sid:1000001; rev:1;)`  

To utilise the rule and inspect the given pcap-file, I'll use the following command inside the `TASK-3 (FTP)` folder: `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`  

### What is the number of detected packets?
> 307

### What is the FTP service name?
I figured the service name would show quite early in the traffic.  
I used `snort -r snort.log.{unix-timestamp} -X -n 5`.
`-X` prints the raw data from the link layer. `-d` could also have been used, as it dumps the data from the application layer.
The answer shows in Packet 4.
> Microsoft FTP Service

## Deactivate old rules, and write a rule to detect failed FTP login attempts in the given pcap.
Looking at [FTP server return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes) there are a few possible things to look at, but `530` might be useful. This would require inspecting the content of the packet for any `530`. `content` can be useful for this.  

The new rule would then be: `alert tcp any any <> any any (msg:"FTP failed login"; content:"530"; sid:1000001; rev:1;)`

### What is the number of detected Packets?
> 41

## Deactivate old rules, and write a rule to detect successful FTP logins in the given pcap.
Looking at the same links as earlier, the `230` might be useful.

The new rule would then be: `alert tcp any any <> any any (msg:"FTP login succeessful"; content:"230"; sid:1000001; rev:1;)`

### What is the number of detected Packets?
> 1

## Deactivate old rules, and write a rule to detect FTP login attempts with a valid username but no password entered yet.
Again, the link is useful. `331` looks promising.

The new rule would then be: `alert tcp any any <> any any (msg:"Username OK, password needed"; content:"331"; sid:1000001; rev:1;)`

### What is the number of detected Packets?
> 42

## Deactivate old rules, and write a rule to detect FTP login attempts with the "Administrator" username, but no password entered yet.
This one requires combining `331` along with the given username.

The new rule would then be: `alert tcp any any <> any any (msg:"User Admin, Password needed"; content:"Administrator"; content:"331"; sid:1000001; rev:1;)`

### What is the number of detected Packets?
> 7

***

# Task 4 - Writing IDS Rules (PNG)
## Write a rule to detect the PNG file in the given pcap.


***

# Task 5 - Writing IDS Rules (Torrent Metafile)
