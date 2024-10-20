# Blues V Joes Bsides2024
 
## Sha0l1n-Shadow-Stealers

Our team placed first in the BSidesNYC 2024 Pros Vs Joes competition. 


### Team Members

- Cyb0rgSw0rd [Captain]
- Alexi Garyn
- fG
- DatainTheStone
- drewshadow
- jest
- kfudge
- lyn
- mahmoud
- scarx4353

## Defensive Tactics

During the first part of the competition we were tasked specifically with defending our infrastructure. It was a little unorganized, and we weren't really sure what was what - so while some teammates did recon on our own networks, others focused on threat management.

### Infrastructure Enumeration

Since we were given very little knowledge of what we were going to be facing in advance, we needed teams to run in and identify what was running where.

`uname -a` - We needed to know what we were working with to begin with! Old Ubuntus (14.*), Windows XP, servers, etc.
`netstat -tuln` might tell us any open connections already on the machines
`netstat` would give a lot more information
`ps aux | grep <whatever>` - often we were looking for bad SSH'ers coming in.

#### Something we did not do, but should have done...
`tcpdump` - we should've identified any signals coming to/from our machine

### Threat Management

One of the first things our teams did when coming in was check which binaries were being used, who was on the server, and tried to isolate and remove any SSH Keys that did not belong to our team.

To check which binaries were in use, using `which which` or `which apt` or `which <whatever>` would tell us where/what was being used.

Once we were reasonably confident in the binaries that existed we could port over different binaries to replace existing bins or just run a full `apt update && apt upgrade -y`. This would help mitigate some things.

**Any changed binaries?** `debsums -c` gave us a good insight into that. While which could work for identifying bins running from places they should not have been, we'd have to manually check each hash against existing. However, this isn't foolproof and could be faked.

**Who is on our network** - `who` told us who was logged in and where. Because of proxmox the number of times we accidentally killed our own connections is embarassing, but it does get confusing with duplicate logins, to be fair.

**Any rootkits?** - Getting chkrootkit and rkhunter running helped ID any rootkits in place.

**Where does my text go?** - You can modify the bash profiles to echo text somewhere... and we had to ensure this wasn't the case.

Once that was done - we changed the passwords from a predefined list shared internally. Every time a password may have been compromised we changed it. Or should have! 

## Offensive Tactics

We didn't know much about the network and admittedly could not attack much during this. The attacks against our team were a bit too heavy, so a strong defense was the best offense we could play. 

### **Network Enumeration**

Midway through the event we were told the ranges of the other teams. From that point forward we could attack or they could attack us. Running an nmap scan of these networks helped for us to identify what IPs they had, and what services were running where.
