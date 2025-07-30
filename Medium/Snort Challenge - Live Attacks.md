# [Snort Challenge - Live Attacks](https://tryhackme.com/room/snortchallenges2)

![snort commands](<../Helpful Files/snort-101-commands.png>)

![snort rule breakdown](<../Helpful Files/snort-101-rule-breakdown.png>)

***

# Task 2 - Scenario 1 | Brute-Force
First of all, start Snort in sniffer mode and try to figure out the attack source, service, and port.

Then, write an IPS rule and run Snort in IPS mode to stop the brute-force attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:  
Create the rule and test it with "-A console" mode.  
Use "-A full" mode and the default log path to stop the attack.  
Write the correct rule and run Snort in IPS "-A full" mode.  
Block the traffic for at least a minute, and then the flag file will appear on your desktop.

*** 

Executing `sudo snort -v -l .` starts Snort in sniffing mode and saves a log in the directory where the terminal is launched (in this case, on the desktop).  
After retrieving a log, I inspected it with `sudo snort -r {log} -X` to find anything interesting.

Using this, I found packets containing various names of certs, cryptographic algorithms, and URLs, all being sent to port 22 on a machine. Port 22 is reserved for SSH, so this definitely warrants further investigation.

`alert tcp 10.10.245.36 any -> any 22 (msg:"10.10.245.36 att. conn. port 22"; sid:1000001; rev:1;)`  

This rule will focus on any traffic from `10.10.245.36:{any port}` going to `{any IP}:22`, meaning any SSH-focused traffic from the IP to any port 22.

After verifying that this in fact finds several packets containing SSH-related items, I rewrite the rule to drop the packets instead of alerting me of them. Simply replace `alert` with `drop`.  
To verify that the rule is useful, I run `sudo snort -c local.rules -T`, which tells me it is functional.

Executing this as IPS requires `sudo snort -c local.rules -Q --daq afpacket -i eth0:eth1 -A full`, and the flag is revealed shortly after.

### Stop the attack and get the flag (which will appear on your Desktop)
> THM{81b7fef657f8aaa6e4e200d616738254}

### What is the name of the service under attack?
> SSH

### What is the used protocol/port in the attack?
> TCP/22

***

# Task 3 - Scenario 2 | Reverse Shell
First of all, start Snort in sniffer mode and try to figure out the attack source, service, and port.

Then, write an IPS rule and run Snort in IPS mode to stop the attack. Once you stop the attack properly, you will have the flag on the desktop!

Here are a few points to remember:  

Create the rule and test it with "-A console" mode.  
Use "-A full" mode and the default log path to stop the attack.  
Write the correct rule and run Snort in IPS "-A full" mode.  
Block the traffic for at least a minute, and then the flag file will appear on your desktop.

***

Initial recon requires `sudo snort -v -l .` to sniff packets and save them in a log for further inspection.

Upon further inspection, I see what resembles a reverse shell sending its IP. Other packets are also sending what seems to be the result of an `ls` in the home directory, strongly indicating access to a compromised client.

To further investigate this, I set up a rule to focus on the compromised client:  
`alert tcp 10.10.196.55 any <> any any (msg:"x.x.196.55 sending"; sid:1000001; rev:1;)`

Testing with `sudo snort -c local.rules -T` returned no errors, so I proceeded.

Running a quick test with the new rule and inspecting the log brings another detail to my attention—the fact that the destination port is `4444`, which is usually associated with malicious actors, e.g., Metasploit.

Another quick run with `alert tcp 10.10.196.55 any <> any 4444 (msg:"x.x.196.55 sending to port 4444"; sid:1000001; rev:2;)` reveals a lot of traffic in a very short time.

Time to properly run this:  
`sudo snort -c local.rules -Q --daq afpacket -i eth0:eth1 -A full`

After a brief run, `flag.txt` appears on the Desktop.

### Stop the attack and get the flag (which will appear on the Desktop)
> THM{0ead8c494861079b1b74ec2380d2cd24}

### What is the used protocol/port in the attack?
> TCP/4444

### Which tool is highly associated with this specific port number?
> Metasploit