# [TShark Challenge II: Directory](https://tryhackme.com/room/tsharkchallengetwo)

## Challenge Description:
An alert has been triggered: "A user came across a poor file index, and their curiosity led to problems."

The case was assigned to you. Inspect the provided **directory-curiosity.pcap** located in `~/Desktop/exercise-files` and retrieve the artefacts to confirm that this alert is a true positive.

Your tools: TShark, [VirusTotal](https://www.virustotal.com/gui/home/upload)

Investigate the DNS queries.

Investigate the domains by using VirusTotal.

According to VirusTotal, there may be domains or files marked as malicious/suspicious.

***

### What is the name of the malicious/suspicious domain? Enter your answer in a **defanged** format.

A quick check with `tshark -r directory-curiosity.pcap -T fields -e ip.src -e ip.dst -e http.host -E header=y | sort | uniq -c` will reveal a few different hostnames, but the one that stands out to me was the correct answer. Luckily, utilising `uniq -c` immediately grants the answer to the next 2 questions as well.

> jx2-bavuong[.]com

***

### What is the total number of HTTP requests sent to the malicious domain?

> 14

***

### What is the IP address associated with the malicious domain? Enter your answer in a **defanged** format.

Remember to defang.

> 141[.]164[.]41[.]174

***

### What is the server info of the suspicious domain?

Now that we know what IP to look at, we can simply extract the server info from relevant packets:

`tshark -r directory-curiosity.pcap -T fields -e http.server -Y 'ip.src==141.164.41.174' | sort | uniq`

> Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9

***

### Follow the "first TCP stream" in "ASCII". Investigate the output carefully. What is the number of listed files?

Utilising `tshark -r directory-curiosity.pcap -z follow,tcp,ascii,0 -q | nl` follows the requested stream. `nl` helps give a good visual setup. Reading the content of the stream will reveal the answer. This should also help you to find the answer for the next question.

> 3

***

### What is the filename of the first file? Enter your answer in a **defanged** format.

> 123[.]php

***

### Export all HTTP traffic objects. What is the name of the downloaded executable file? Enter your answer in a **defanged** format.

Export the objects with `tshark -r directory-curiosity.pcap --export-objects http,. -q`, and find the requested file.

> vlauto[.]exe

***

### What is the SHA256 value of the malicious file?

Utilising `sha256sum {malicious-file.name}` grants us the answer.

> b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de

***

### Search the SHA256 value of the file on VirtusTotal. What is the "PEiD packer" value?

The answer can be found in the Details tab.

> .NET executable

***

### Search the SHA256 value of the file on VirtusTotal. What does the "Lastline Sandbox" flag this as?

The answer can be found in the Behavior tab.
Checking the `Dynamic Analysis Sandbox Detections` section will reveal this quickly.

> Malware Trojan