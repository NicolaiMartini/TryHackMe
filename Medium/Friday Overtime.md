# [Friday Overtime](https://tryhackme.com/room/fridayovertime)

## Challenge Description:
It's a Friday evening at PandaProbe Intelligence when a notification appears on your CTI platform. While most are already looking forward to the weekend, you realise you must pull overtime because SwiftSpend Finance has opened a new ticket, raising concerns about potential malware threats. The finance company, known for its meticulous security measures, has stumbled upon something suspicious and wants immediate expert analysis.

As the only remaining CTI Analyst on shift at PandaProbe Intelligence, you quickly take charge of the situation, realising the gravity of a potential breach at a financial institution. The ticket contains multiple file attachments, presumed to be malware samples.

With a deep breath, a focused mind, and the longing desire to go home, you begin the process of:

1. Downloading the malware samples provided in the ticket, ensuring they are contained in a secure environment.
2. Running the samples through preliminary automated malware analysis tools to get a quick overview.
3. Deep diving into a manual analysis, understanding the malware's behaviour, and identifying its communication patterns.
4. Correlating findings with global threat intelligence databases to identify known signatures or behaviours.
5. Compiling a comprehensive report with mitigation and recovery steps, ensuring SwiftSpend Finance can swiftly address potential threats.

***

### Who shared the malware samples?

As soon as you log onto the website, you'll be greeted with the ticket for the suspected malware. Reading the ticket will reveal the answer.

> Oliver Bennett

***

### What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?

Download the zip archive, extract it using the password from the ticket, and get the hash from the file by using: `sha1sum pRsm.dll`

> 9d1ecbbe8637fed0d89fca1af35ea821277ad2e8

***

### Which malware framework utilizes these DLLs as add-on modules?

Searching for the SHA1 sum on [VirusTotal](http://virustotal.com/) presents a highlight named "Popular threat label". Searching for the information found here leads to a page on [MITRE ATT&CK](https://attack.mitre.org/software/S1146/) regarding "MgBot", and the page specifies quite a few different flavours of modules the malware can utilise.

There's also plenty of information in the "Community" tab on VirusTotal.com.

> MgBot

***

### Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?

Looking at the "Community" tab on VirusTotal.com, there's a recent post with a link to an [article](https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/) regarding this specific piece of malware. Reading through it, you'll come across the purpose of the DLL, which is to capture audio from the infected client.

With this information available, you can take a look at the MITRE ATT&CK page or even the [ATT&CK Navigator page](https://mitre-attack.github.io/attack-navigator//#layerURL=https%3A%2F%2Fattack.mitre.org%2Fsoftware%2FS1146%2FS1146-enterprise-layer.json) to find the technique that is used by pRsm.dll.

> T1123

***

### What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02? 

Reading the article from welivesecurity reveals this answer.

> `hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe`

***

### What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?

This can also be found in the article from welivesecurity.

> 122[.]10[.]90[.]12

***

### What is the MD5 hash of the spyagent family spyware hosted on the same IP targeting Android devices in June 2025?

Going back to VirusTotal with the IP address and searching for it will reveal a page connected to Hong Kong. Looking under the "Relations" tab, you'll come across a file type connected to "Android". This page will have the answer, in the "Details" tab.

> 951f41930489a8bfe963fced5d8dfd79