# [Eviction](https://tryhackme.com/room/eviction)

## Challenge Description:
Sunny is a SOC analyst at E-corp, which manufactures rare earth metals for government and non-government clients. She receives a classified intelligence report that informs her that an APT group (APT28) might be trying to attack organizations similar to E-corp. To act on this intelligence, she must use the MITRE ATT&CK Navigator to identify the TTPs used by the APT group, to ensure it has not already intruded into the network, and to stop it if it has.

Please visit [this link](https://static-labs.tryhackme.cloud/sites/eviction/) to check out the MITRE ATT&CK Navigator layer for the APT group and answer the questions below.

***

### What is a technique used by the APT to both perform recon and gain initial access?

Looking at the Navigator, you'll notice that `Spearphishing Link` is a subtechnique under both `Reconnaissance > Phishing for Information` and `Initial Access > Phishing`.

> Spearphishing Link

***

### Sunny identified that the APT might have moved forward from the recon phase. Which accounts might the APT compromise while developing resources?

Looking at `Resource Development`, the only accounts highlighted here are `Email Accounts`.

> Email Accounts

***

### E-corp has found that the APT might have gained initial access using social engineering to make the user execute code for the threat actor. Sunny wants to identify if the APT was also successful in execution. What two techniques of user execution should Sunny look out for? (Answer format: <technique 1> and <technique 2>)

Since social engineering was involved, check `Execution > User Execution` for relevant subtechniques.

> Malicious File and Malicious Link

***

### If the above technique was successful, which scripting interpreters should Sunny search for to identify successful execution? (Answer format: <technique 1> and <technique 2>)

To find scripting interpreters, refer to `Execution > Command and Scripting Interpreter`.

> PowerShell and Windows Command Shell

***

### While looking at the scripting interpreters identified in Q4, Sunny found some obfuscated scripts that changed the registry. Assuming these changes are for maintaining persistence, which registry keys should Sunny observe to track these changes?

Since the script was for persistence and modified registry keys, check `Persistence > Boot or Logon Autostart Execution`.

> Registry Run Keys

***

### Sunny identified that the APT executes system binaries to evade defences. Which system binary's execution should Sunny scrutinize for proxy execution?

For defense evasion using system binaries, see `Defense Evasion > System Binary Proxy Execution`.

> Rundll32

***

### Sunny identified tcpdump on one of the compromised hosts. Assuming this was placed there by the threat actor, which technique might the APT be using here for discovery?

Since tcpdump was used, the relevant technique in `Discovery` should be apparent.

> Network Sniffing

***

### It looks like the APT achieved lateral movement by exploiting remote services. Which remote services should Sunny observe to identify APT activity traces?

Refer to `Lateral Movement > Remote Services` for the answer.

> SMB/Windows Admin Shares

***

### It looked like the primary goal of the APT was to steal intellectual property from E-corp's information repositories. Which information repository can be the likely target of the APT?


`Collection > Data from Information Repositories` should be easy to locate.

> SharePoint

***

### Although the APT had collected the data, it could not connect to the C2 for data exfiltration. To thwart any attempts to do that, what types of proxy might the APT use? (Answer format: <technique 1> and <technique 2>)

See `Command and Control > Proxy` for the answer.

> External Proxy and Multi-hop Proxy
