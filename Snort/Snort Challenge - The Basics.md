![[Snort-101.pdf]]
# Task 1 - Writing IDS Rules (HTTP)

> [!info]
> Write a rule to detect all TCP packet **from or to** port 80.

> [!question]- What is the number of detected packets from or to port 80?
> Answer: 164
> > [!cite]-
> > `alert tcp any 80 <> any any (msg:"TCP Packet Found", sid:1000001; rev:1;)`
> > `sudo snort -c local.rules -A full -l . -r  `

# Task 5 - Writing IDS Rules (Torrent Metafile)

> [!info]
> Use the given pcap file.
> Write a rule to detect the torrent metafule in the given pcap. 


> [!question]- What is the number of detected packets?
> ``
