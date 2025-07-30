# [Summit](https://tryhackme.com/room/summit)

## Challenge Description:
After participating in one too many incident response activities, PicoSecure has decided to conduct a threat simulation and detection engineering engagement to bolster its malware detection capabilities. You have been assigned to work with an external penetration tester in an iterative purple-team scenario. The tester will be attempting to execute malware samples on a simulated internal user workstation. At the same time, you will need to configure PicoSecure's security tools to detect and prevent the malware from executing.

Following the Pyramid of Pain's ascending priority of indicators, your objective is to increase the simulated adversaries' cost of operations and chase them away for good. Each level of the pyramid allows you to detect and prevent various indicators of attack.

***


### What is the first flag you receive after successfully detecting **sample1.exe**?
First step is to find the malware in the email, click it, and scan it.

The scan will give us some information regarding the behaviour of the malware.

Grab either hash value, open the side menu (hamburger icon in the upper left corner), specify which hash value has been grabbed, and paste the hash. Then submit it.

The flag will be sent in the email, along with the next sample.

> THM{f3cbf08151a11a6a331db9c6cf5f4fe4}

***

### What is the second flag you receive after successfully detecting **sample2.exe**?

Click the new sample and analyse it. 

The new analysis will reveal a bit more information regarding the malware, including the behaviour analysis as in sample 1. Now we get network activity as well. This is relevant in order to prevent this malware going forward.

We can create rules for the firewall, using the firewall rule manager from the side menu.

We can specify a rule with the following:  
Type: Ingress or Egress (activity going in or out)  
Source IP: Self-explanatory.  
Destination IP: Self-explanatory.  
Deny: What we want the firewall to do with activity detected regarding the prior information.

Looking at the network activity, we see activity regarding IP `40.97.128.4:443	`, `40.97.128.3:443` and `154.35.10.113:4444`. Port 443 are reserved to HTTPS, and port 4444 is often seen in relation to Metasploit.

Knowing this, we don't want any outgoing connection to an IP with port 4444.

Type: Egress  
Source IP: Any  
Destination IP: 154.35.10.113  
Action: Deny

> THM{2ff48a3421a938b388418be273f4806d}

***

### What is the third flag you receive after successfully detecting **sample3.exe**?

Analysing sample 3 will now reveal a bit more information - some DNS info.

Making note of the information available, find the side menu regarding DNS Filter.

Enter the relevant information, create the ruler, and go find the flag in the inbox.

> THM{4eca9e2f61a19ecd5df34c788e7dce16}

***

### What is the fourth flag you receive after successfully detecting **sample4.exe**?

Analysing the fourth malware sample will reveal similar information as before, but now there's also some registry activity.

Making note of these, we'll have to add some rules using the Sigma Rule Builder from the side menu.

The rule builder has a few options, but we're interested in the one that is regarding registry keys.

Choosing `Sysmon Event Logs` > `Registry Modifications`  and inputting the relevant information will trigger the next step.

Registry Key: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`  
Registry Name: `DisableRealtimeMonitoring`  
Value: `1`  
ATT&CK ID: `Defense Evasion (TA0005)` 

> THM{c956f455fc076aea829799c0876ee399}

***

### What is the fifth flag you receive after successfully detecting **sample5.exe**?
Looking at the log file attached to the email will reveal a bit of information: A lot of repeat connections to the same IP address (`51.102.10.19`), using the same port (`443`), with the same payload size (`97 bytes`), and predictable interval (`every 30 minutes`).

Looking at the analysis from sample5 we see quite a few items worth noting, since they repeat:  
Process: `beacon.bat`  
Method: `POST`  
IP: `51.102.10.19:443`  
URL:  `https://bababa10la.cn/keep-alive?hostname=WK102`

Combining these informations, we create a rule using the Sigma Rule Builder:   
`Sysmon Event Logs` > `Network Connections`.

Using the information we have at hand will help us create the necessary rule, but we have to remember that the attacker doesn't necessarily remain "staitonary". They might change any utilised IP address or port.

Remote IP: `Any`  
Remote Port: `Any`  
Size: `97`  
Frequency (secconds): `1800`  
ATT&CK ID: `Command and Control (TA0011)`  

> THM{46b21c4410e47dc5729ceadef0fc722e}

***

### What is the final flag you receive from Sphinx?
In the email that is then sent, we get an insight into what commands are being utilised.

```
dir c:\ >> %temp%\exfiltr8.log
dir "c:\Documents and Settings" >> %temp%\exfiltr8.log
dir "c:\Program Files\" >> %temp%\exfiltr8.log
dir d:\ >> %temp%\exfiltr8.log
net localgroup administrator >> %temp%\exfiltr8.log
ver >> %temp%\exfiltr8.log
systeminfo >> %temp%\exfiltr8.log
ipconfig /all >> %temp%\exfiltr8.log
netstat -ano >> %temp%\exfiltr8.log
net start >> %temp%\exfiltr8.log
```

The important information here, is that a location and a file is recurring.  
Information is gathered from various sources, but are all added to the same file, in the same location.

This is the needed information for the final question. 
`Sigma Rule Builder` > `Sysmon Event Logs` > `File Creation and Modification`:
File Path: `%temp%`  
File name: `exfiltr8.log`  
ATT&CK ID: `Collection (TA0009)`  

> THM{c8951b2ad24bbcbac60c16cf2c83d92c}
