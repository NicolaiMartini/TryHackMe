# [Zeek Exercises](https://tryhackme.com/room/zeekbroexercises)

![Corelight Zeek Logs Cheatsheet](../Helpful%20Files/Corelight-Zeek-Logs.png)

Task 1 is merely an introduction telling the user to utilise the built-in VM.
In Task 1, it is also recommended that the user complete the [Zeek room](https://tryhackme.com/room/zeekbro) before doing this one.

Exercises for each task are located on the desktop: `~/Desktop/Exercise-Files/`

***

# Task 2 - Anomalous DNS
## Investigate the `dns-tunneling.pcap` file. 
### Investigate the  `dns.log` file. What is the number of DNS records linked to the IPv6 address?
Investigating `dns.log` revealed a lot of info, most of it not relevant to this question. Scrolling through the wall of text did reveal that the type of lookup was entered as `qtype_name`. This means that query types were saved in the log as the following:  
```
A  
AAAA  
CNAME  
MX  
PTR  
TXT
```

From there, it was a matter of isolating the log by `qtype_name`, sorting the output, isolating it to `AAAA`, and counting the number of instances.  
The full command I used was:  
`cat dns.log | zeek-cut qtype_name | sort | grep "AAAA" | wc -l`  
  
Answer:  
> 320

### Investigate the `conn.log` file. What is the longest connection duration?
Investigating the `conn.log` with `cat conn.log | head -n 10` quickly reveals a field aptly named `duration`.  
The answer is quickly found with the command:  
`cat conn.log | zeek-cut duration | sort -n | tail -n 1`  

Answer:  
> 9.420791

### Investigate the `dns.log` file. What is the number of unique domain queries?
A quick glance at the `query` field from `dns.log` will reveal a massive number of subdomains (over 6000), but we're only interested in the `Second-Level Domain` for this question.  
Utilising our knowledge of DNS, we'll quickly find the answer with the command: `cat dns.log | zeek-cut query | rev | cut  -d '.' -f 2 | rev | sort | uniq` 

Breakdown:  
`cat dns.log | zeek-cut query` should be self-explanatory by now.  
`rev` reverses the output. This is relevant because of the scheme, the build-up of the DNS and the layout of the output, since we're only interested in the `SLD`. This combines with the following:  

`cut -d '.' -f 2` - cut is used to cut away anything not specified, which in this case is the second field between any `.`. Remember that we reversed the queries, meaning "subdomain.sld.tld" becomes "dlt.dls.niamodbus". The `cut` command with the arguments specifies we're only interested in "dls" in this example.  
`rev | sort | uniq` should be self-explanatory again, but for good measure, it means "reverse again, sort, and only list uniques". This leaves us with the answer.

The commands `wc -l` or `nl` could be appended to the full command to make counting easier, but counting in this specific scenario shouldn't be an issue.

Answer: 
> 6

### Investigate the `conn.log` file. What is the IP address of the source host?
The answer is found quickly after viewing the contents of `conn.log`.  
The full command I used for good measure:  
`cat conn.log | zeek-cut id.orig_h | sort | uniq -c`

Answer:  
> 10.20.57.3

***

# Task 3 - Phishing
## An alert triggered: "Phishing Attempt". The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

### Investigate the logs. What is the suspicious source address? Enter your answer in `defanged format`.
To start, we'll have to get some useful formats by using `zeek -C -r phishing.pcap`.  
A quick inspection of `conn.log` reveals only one IP address, and defanging it quickly with CyberChef gave us the proper answer.

Answer:
> 10[.]6[.]27[.]102

### Investigate the `http.log` file. Which domain address were the malicious files downloaded from? Enter your answer in `defanged format`.
A quick peek into `http.log` reveals three GET requests, two of them to the same domain, related to a `.doc` file and a `.exe` file.  
Again, utilising CyberChef to defang can be useful, but in this case, it's just as fast (if not faster) to do it manually.

Answer: 
> smart-fax[.]com

### Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?
I figured a safe way to investigate the malicious file would be with a checksum, but to get one, we'll have to extract the file. To extract the file, we'll use `file-extract-demo.zeek`:  
`zeek -C -r phishing.pcap file-extract-demo.zeek`  
The extracted files will then be found in the `extracted_files` folder, and by using `file` with the file name, we can identify the file we want to investigate.  
Once we have the name, we'll generate a SHA256 checksum of the file with `sha256sum {file name}`, which we can then search for in VirusTotal.

Looking under `Relations` in the section `Bundled Files`, we'll see a detection higher than the others, which reveals the file type to us.

Note that the question is regarding a "document".

> VBA

### Investigate the extracted malicious .exe file. What is the given file name in VirusTotal?
This can be found next to the file's score on VirusTotal.
> PleaseWaitWindow.exe

### Investigate the malicious .exe file in VirusTotal. What is the contacted domain name? Enter your answer in `defanged format`.
In the "Contacted Domains" section on VirusTotal, there's a domain that has a higher detection than the rest. This URL includes a subdomain, but we're only interested in the SLD. CyberChef can defang, or we can do this one quickly manually as well.
> dhopto[.]org

### Investigate the `http.log` file. What is the request name of the downloaded malicious `.exe` file?
This one should be rather quick to find as well. There's only one `.exe` file to be spotted in the `http.log`.
> knr.exe

***

# Task 4 - Log4J
## An alert triggered: "Log4J Exploitation Attempt". The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

### Investigate the `log4shell.pcapng` file with `detection-log4j.zeek` script. Investigate the `signature.log` file. What is the number of signature hits?
To start, run `zeek -C -r log4shell.pcapng detection-log4j.zeek`.  
A quick `cat` gives us the answer.

Answer:
> 3

### Investigate the `http.log` file. Which tool is used for scanning?
A quick `cat` should reveal the answer to this one as well.

> nmap

### Investigate the `http.log` file. What is the extension of the exploit file?
This one can be answered by utilising `head` with `cat`, and looking for any extension names:  
`cat http.log | head -n 20`

> .class

### Investigate the `log4j.log` file. Decode the base64 commands. What is the name of the created file?
`cat log4j.log` and inspect the given fields.  
`cat log4j.log | zeek-cut value | more` to only look at the values of each entry, and to limit how many are outputted, so as not to be overwhelmed. Looking at the first base64 entry, and decoding with CyberChef, we get the answer.

> pwned