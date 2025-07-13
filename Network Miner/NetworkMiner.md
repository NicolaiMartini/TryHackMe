# [Network Miner](https://tryhackme.com/room/networkminer)

The first 3 tasks are introduction to Network Miner.  
Most of Task 4 is as well.

***

# Task 4 - Tool Overview 1
## Use mx-3.pcap
### What is the total number of frames?
To find this, I load mx-3.pcap into NetworkMiner 2.7.2 (as depicted in the screenshots in the room), and inspect the file in the `Case Panel` -> `Show Metadata`.
> 460

### How many IP addresses use the same MAC address with host 145.253.2.203?
Checking under `Hosts`, expanding the corresponding `IP` address field, and then the `MAC`-field.
> 2

### How many Packets were sent from host 65.208.228.223?
In `Hosts`, expanding the corresponding `IP`, it quickly states the amount of sent and received Packets.
> 72

### What is the name of the webserver banner under host 65.208.228.223?
Checking further down in the same IP address under `Host Details`, we'll find the requested information.
> Apache

## Use the mx-4.pcap
### What is the extracted username?
This can be found under `Credentials` in the main window.
> #B\Administrator

### What is the extracted password?
This can also be found in the `Credentials` menu in the main window.

> NETNTLMv2$#B$136B077D942D9A63$FBFF3C253926907AAAAD670A9037F2A5$01010000000000000094D71AE38CD60170A8D571127AE49E00000000020004003300420001001E003000310035003600360053002D00570049004E00310036002D004900520004001E0074006800720065006500620065006500730063006F002E0063006F006D0003003E003000310035003600360073002D00770069006E00310036002D00690072002E0074006800720065006500620065006500730063006F002E0063006F006D0005001E0074006800720065006500620065006500730063006F002E0063006F006D00070008000094D71AE38CD601060004000200000008003000300000000000000000000000003000009050B30CECBEBD73F501D6A2B88286851A6E84DDFAE1211D512A6A5A72594D340A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E00360036002E0033003600000000000000000000000000

***

# Task 5 - Tool Overview 2
## Use mx-7.pcap
### What is the name of the Linux distro mentioned in the file associated with frame 63075?
Going to `Files` and changing `Any column` in the search bar to `Frame nr.` allows us to search specifically for frame 63075.
In the `source host` we see the requested information.
> centos

### What is the  header of the page associated with frame 75942?
Searching for the Frame nr in `Files`, and inspecting it gives us the content of the Frame.
> Password-Ned AB

### What is the source address of the image `ads.bmp.2E5F0FD9.bmp`?
Search for the image-name in the `Files` tab, inspect the frame, and copy the source from the new window.
> 80.239.178.187

### What is the frame number of the possible TLS anomaly?
This can be found in the `Anomalies` tab.
> 36255

## Use the mx-9.pcap
### Look at the messages. Which platform sent a password reset email?
Going to `Messages` quickly reveals a few threads, and what is disguised as a facebook email, although it does not look very legit.
> Facebook

### What is the email address of Branson Matheson?
Looking at a thread with Branson Matheson reveals his email address.
> branson@sandsite.org

***

# Task 6 - Version Differences
Most of this section is useful information.  
They are mostly focused on differences between v1.6 and v2.7.  

### Which version can detect duplicate MAC addresses?
> 2.7

### Which version can handle Frames?
> 1.6

### Which version can provide more details on Packets?
> 1.6

***

# Task 7 - Exercises
## Use case1.pcap
### What is the OS name of the host 131.151.37.122?
Looking under `Hosts` and under the corresponding IP address's `OS: Windows` gives us the answer.
> Windows - Windows NT 4 

### Investigate the hosts 131.151.37.122 and 131.151.32.91. How many data bytes were received from host 131.151.32.91 to host 131.151.37.122 through port 1065?
Dissecting the question first, we can either look at `x.x.37.122` or `x.x.32.91` to begin with. I chose to look at `37.122` and inspecting the incoming traffic through port 1065.
This means unfolding the `IP address`, the `Incoming Sessions`, the corresponding `server` and finding the part that tells us about the bytes sent from the other IP.
> 192

### Investigate the hosts 131.151.37.122 and 131.151.32.21. How many data bytes were received from host 131.151.37.122 to host 131.151.32.21 through port 143?
Largely following the same steps as before, just looking at the sent bytes from the Windows client.
> 20769

### What is the sequence number of frame 9?
This one requires us to open the case1.pcap in NetworkMiner 1.6.  
In here we open `Frames`, find the 9th Frame, check `TCP` and the answer is given to us.
> 2AD77400

### What is the number of the detected "content types"?
In NetworkMiner v1.6, we can search for Content-Type in `Keywords`, and in `Context` see the different kinds of Content-Type present.
> 2

### Use case2.pcap and investigate the files. What is the USB product's brand name?
Looking in `Images` Asix shows up in a few photos.  
A quick search shows that Asix develops various types of IT products, e.g. USB connections of various types.
> Asix

### What is the name of the phone model?
Looking around in `Images` we'll find a few phones, and the answer is found in the file-name.
> Lumia 535

### What is the source IP of the fish image?
Looking around in `Images` we'll find the details by hovering the mouse pointer over the image, and the source and destination (among other things) will show themselves.
> 50.22.95.9

### What is the password of the "homer.pwned.se@gmx.com"?
Looking in `Credentials` the answer quickly stands out as the sole `Pop3` protocol in a sea of `HTTP cookies`.
> spring2015

### What is the DNS Query of frame 62001?
In `DNS` we search for `Frame nr.` 62001, and the answer is given to us.
> pop.gmx.com