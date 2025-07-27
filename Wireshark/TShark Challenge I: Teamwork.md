# [TShark Challenge I: Teamwork](https://tryhackme.com/room/tsharkchallengesone)

## Challenge Description:
An alert has been triggered: "The threat research team discovered a suspicious domain that could be a potential threat to the organisation."

The case was assigned to you. Inspect the provided **teamwork.pcap** located in `~/Desktop/exercise-files` and create artefacts for detection tooling.

Your tools: TShark, [VirusTotal](https://www.virustotal.com/gui/home/upload)

Investigate the contacted domains.

Investigate the domains by using VirusTotal.

According to VirusTotal, there is a domain marked as malicious/suspicious.

***

### What is the full URL of the malicious/suspicious domain address? Enter your answer in **defanged** format.

I found the full URL by inspecting the pcap to see if there was anything interesting, and it did not take much scrolling.

> `hxxp[://]www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com/`

***

### When was the URL of the malicious/suspicious domain address first submitted to VirusTotal?

This one was a bit tricky. Simply searching for the URL found in the pcap leads to a site on VirusTotal with useful information, but does not provide the answer to this question.

To find the answer, a **full** URL has to be passed, meaning `http://` needs to be added to the result from the pcap.

The answer can then be found in the Details tab.

> 2017-04-17 22:52:53 UTC

***

### Which known service was the domain trying to impersonate?

This should be a dead giveaway from question 1.

> PayPal

***

### What is the IP address of the malicious domain? Enter your answer in **defanged** format.

Looking at question 1, the IP address is connected to the malicious URL.

Utilising `tshark -r teamwork.pcap -T fields -e ip.dst -e http.host | sort | uniq` reveals the IP address.

> 184[.]154[.]127[.]226

***

### What is the email address that was used? Enter your answer in **defanged** format (**format**: aaa[at]bbb[.]ccc).

The email can be found with `tshark -r teamwork.pcap -x -Y 'http.request.method == "POST"'` and by looking through the contents.

> johnny5alive[at]gmail[.]com