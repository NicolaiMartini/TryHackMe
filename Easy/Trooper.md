# [Trooper](https://tryhackme.com/room/trooper)

## Challenge Description:
A multinational technology company has been the target of several cyber attacks in the past few months. The attackers have been successful in stealing sensitive intellectual property and causing disruptions to the company's operations. A threat advisory report about similar attacks has been shared, and as a CTI analyst, your task is to identify the Tactics, Techniques, and Procedures (TTPs) being used by the Threat group and gather as much information as possible about their identity and motive. For this task, you will utilise the OpenCTI platform as well as the MITRE ATT&CK navigator, linked to the details below. 



***

### What kind of phishing campaign does APT X use as part of their TTPs?

Can be found by reading the PDF.

> spear-phishing emails

***

### What is the name of the malware used by APT X?

Can be found by reading the PDF.

> USBferry

***

### What is the malware's STIX ID?

The VM will be given an IP along with a port for OpenCTI. Logging into the OpenCTI website with the given credentials, and searching for the malware will grant the answer to this question under `BASIC INFORMATION`.

> malware--5d0ea014-1ce9-5d5c-bcc7-f625a07907d0

***

### With the use of a USB, what technique did APT X use for initial access?

Referring to ATT&CK Navigator, referenced in the challenge, we'll find the answer in `Initial Access`.

> Replication through removable media

***

### What is the identity of APT X?

In the PDF, there is a link to TrendMicro's article regarding APT X, which states a different name, that is used as the answer for this question.

> Tropic Trooper

***

### On OpenCTI, how many Attack Pattern techniques are associated with the APT?

We can find the answer in `Tropic Trooper > Knowledge > DISTRIBUTION OF RELATIONS`.

> 39

***

### What is the name of the tool linked to the APT?

Find and click `Tools` in the right side menu.

> BITSadmin

***

### Load up the Navigator. What is the sub-technique used by the APT under Valid Accounts?

`Tropic Trooper > Overview > EXTERNAL REFERENCES` contains a link to the MITRE ATT&CK page for this group. On that page, we can find a link to the ATT&CK Navigator regarding this group.

In this page of the Navigator, we'll see the answer to this question.

This can also be found in the `Tropic Trooper > Knowledge > TIMELINE`, but not as clearly stated as in the Navigator.

> Local Accounts

***

### Under what Tactics does the technique above fall?

A quick way to find this answer is to take a look at the subtechnique's page at [MITRE ATT&CK](https://attack.mitre.org/techniques/T1078/003/) and reading through the first few lines.

> Initial Access, Persistence, Defense Evasion and Privilege Escalation

***

### What technique is the group known for using under the tactic Collection?

A quick look at the Navigator in `Collection` will show the answer.

> Automated Collection

***
