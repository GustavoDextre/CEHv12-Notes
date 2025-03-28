# Chapter 10: Trojans and Other Attacks

## The "Malware" Attacks

*Malware* is fenerally defined as software designed to harm or secretly access a computer system without the owner's informed consent.

Some malware components definitions, the following list doesn't include every single variant in the malware world - some may use all or only some of the entire list:
- **Malicious code**: A command that delineates the basic functionality of the malware (e.g. stealing data)
- **Payload**: A piece of software allowing control over the target after exploitation, or performing the intended action of the attacker.
- **Exploit**: The code that takes advantage of system vulnerabilities to access data or install malware.
- **Injector**: An application that injects its own code into running processes to alter execution (also used in hiding and removal prevention).
- **Downloader**: A Trojan that downloads other malware from an Internet connection (installed by an attacker after access to help with maintaining access).
- **Dropper**: A Trojan type that installs other malware on the compromised system covertly.
- **Obfuscator**: A malicious program that camouflages its code and intended purpose.

EC Council defines seven different methods attackers use to distribute malware:

- Malversting: embedding malware straight into those annoying ad networks you see popping up onscreen everywhere.
- Drive-by-downloads: exploit flaws in the browser software itself to install malware simply by visiting a page.
- Compromised legitimate sites: leading to infections on visiting systems.
- Clickjacking: misleading users into clicking a page that looks innocent enough, but holds malware ready to go.
- SPAM e-mails: the old tried-and-true method of putting malware as an attachment to and e-mail and getting the target to click it.
- Black Hat Search Engine Optimization (SEO): can be used to rank malware sites highest in search engine results.
- Spear phsihing sites: can be used to mimic authentic businesses, allowing the theft of credentials.

> Overt channels are legitimate communication channels used by programs across a system or a network, whereas covert channel are used to trnasport data in unintended ways.

There are some ways to make our malware to look like a legitimate application: 
- Wrappers: are programs that allow you to bind an executable of your choice (Trojan) to an innocent file your target won't mind opening. We can use programs such as:
  - EliteWrap -> e.g. to embed a backdoor application with a game file (.exe)
  - IExpress Wizard -> IExpress.exe is part of Windows deployments since 2000.

Assuming that we got a user that opened the malware, there could be blocked by anti-malware system. So, here is when *Packers* and *crypters* are useful methods to bypass. These are tools that alter malware to hide it from signature-based anti-malware.

- Crypters: are software tools that use a combination of encryption and code manipulationto render malware undetectable to AV and other security-monitoring products (in Internet lingo, it's referred to as *fud*, for "fully undetectable").
- Packers: use compression to pack the malware executable into a smaller size. Due to the reduction of its size, it makes it hard to detect for some anti-malware engines.

Both of them work much like a ZIP file, except that the extraction occurs in memory and not on the disk.

Some crypters to mention: 
- BitCrypter
- CypherX
- Crypter
- SwayzCryptor

And exploit kits, such as Infinity, Bleeding Life, Crimepack, and Blackhole Exploit Kit.

> There are specific actions to take to evade AV on a system we're trying to infect. A few examples include breaking the Trojan into multiple segments and zipping them into a single file, converting an executable to VB script, and changing file extentions to match a known file type other than .exe. We can also use a hex editor to change the checksum for a file. And don't forget encryption.
---
<u>**Trojans**</u>
<br>It is a software that appears to perform a desirable function for the user prior to running or installing it but instead performs a function, usually without the user's knowledge, that steals information or otherwise harms the system (or data). To hackers, it is a method to gain, and maintain, access on a target machine.

There are several categories for Trojans:
- Defacement Trojan -> e.g. change title bar in Excel spreadsheet.
- Proxy Server Trojan -> allows an attacker to use the target system as a proxy.
- Botnet Trojans -> such as Tor-based ChewBacca and Skynet
- Remote Access Trojans -> like RAT, MoSucker, Optix Pro, and Blackhole
- E-banking Trojans -> like Zeus and SpyEye
- Command Shell Trojan -> is intended to provide a backdoor to the system that you connect to via command-line access. e.g. Netcat (known as the "Swiss Army Knife") is not a Trojan, but it can be used to provide a method to backdoor.

> Netcat can be used for outbound or inbound connections, over TCP or UDP, to or from any port on the machine. It offers DNS forwarding, port mapping and forwarding, and proxying. You can even use it as a port scanner if you're really in a bind.

We'll list some default common port numbers used by specific Trojans:

| Trojan Name | Port | 
|---|---|
| Emotet | 20/22/80/443 |
| Dark FTP | 21 | 
| EliteWrap | 23 | 
| Mspy | 68 | 
| Ismdoor, Poison Ivy, powerstats | 80 | 
| WannaCry, Petya | 445 |
| njRAT | 1177 |
| DarkComet, Pandora RAT | 1604 |
| SpySender | 1807 | 
| Xtreme | 1863 |
| Deep Throat | 2140/3150/6670/6671 | 
| Spygate/Punisher RAT | 5000 |
| Blade Runner | 5400-02 | 
| Killer, Houdini | 6666 | 
| Bionet, MagicHound | 6667/12349 | 
| GateCrasher | 6969 |
| Remote Grab | 7000 |
| ICKiller | 7789 | 
| Zeus, Shamoon | 8080 |
| BackOrifice 2000 | 8787/54321 |
| Delf | 10048 |
| Gift | 10100 |
| Senna Spy | 11000 |
| Progenic Trojan | 11223 |
| Hack 99 Keylogger | 12223 |
| Evil FTP | 23456 |
| Back Orifice 1.20/Deep BO | 31337, 31338 |
| Devil | 65000 |

Due to a possible open port, we have the responsibility to check which ports are beign used. For example in windows, there is the **netstat**:

This command will show us all the connections and listening ports in numerical form. Shows all connections in one of several states - everything from SYN_SEND (indicating active open) to CLOSED (the server has received an ACK from the client and closed the connection).
```Powershell
netstat -an
```
![Example of netstat](https://cyberhades.ams3.cdn.digitaloceanspaces.com/imagenes/2008/09/netstat.jpg)

And the next one, displays all active connections and the processes or applications that are using them, which is pretty valuable information in ferreting out spayware and malware.
```Powershell
netstat -b
```
Another option to check ports is CurrPorts from Nirsoft (https://www.nirsoft.net/utils/cports.html) that reports all open TCP/IP and UDP ports and maps them to the owning applications. This tool allow us to close unwanted TCP connections, kill the process that opened the ports, andsave the TCP/UDP ports information to an HTML file, XML file, or tab-delimited text file. Currports aldo automatically marks suspicious TCP/UDP ports owned by unidentified applications for us.

> Process Explorer is a free tool from Windows Sysinternals (https://docs.microsoft.com/sysinternals) that comes highly recommended. Another tool from SysInternals is Autoruns, which is useful to figure out what runs at startup on our system.

In windows, we also may want to check the registry, drivers, and services being used, as well as our startup routines. Some tools are **SysAnalyzer**, **Tiny Watcher**, **Active Registry Monitor**, and **Regshot**. Many anti-malware and malware scanners will watch for registry errors. **Malwarebytes** will display all questionable registry settings it finds on a scan.

> Windows automatically runs everything located in **Run, RunServices, RunOnce, and RunServicesOnce**. These are settings related to HKEY_LOCAL_MACHINE.

Other tools to check service and processes: Windows Service Manager, Service Manager Plus, and Smart Utility.

---
<u>**Viruses and Worms**</u>

- **Virus**: A self-replicating program that reproduces its code by attacjing copies into other executable codes. They usually get installed on a system via file attachements, user clicks on embedded e-mails, or the installation of pirated software, and while some viruses are nothing more than just annoyances.

> *Virus hoax* or *fake anti-malware*: The process involves letting a target know about a terrible virus running rampant through the world and then providing them an anti-malware program (or signature file) to protect themselves with.

Some obvious indicators are: slower response time, computer and browser freezes, and repeated, continual hard drive accesses. 

Others not so obvious: drive letters night change and files and folder may disappear or become inaccesible.

Recovery measures may be a good option to restablish the systems.

> Some options to make your own virus: **Sonic Bat, PoisonVirus Maker, Sam's Virus Generator, and JPS Virus Maker**

**Ransomware**: This is one of the type of malicious software designed to deny access to a computer system or data until a ransom is paid, and tipically spreads through phishing e-mails or by unknowing visits to an infected website. Ransomware locks you out of your own system resources and demands an online payment of some sort in order to release them back to you.

The most famous ransomware and effective in the history so far:
- WannaCry: On May 12, 2017, a system in Asia was the first to fall victim to the WannaCry ransomware. Within the 24 hours, it had spread to over 230,000 machines in 150 countries by taking advantage of an unpatched SMB exploit known as **"Eternal Blue"**.

> The ransomware family includes examples such as Dharma, eCh0raix (targeting Linux devices with QNAP NAS), and SamSam (uses RSA-2048 asymmetric encryption). Some others of note include CryptorBit. CryptoLocker, CryptoDefense, and Petya (a close cousin of WannaCry that spread using the Windows Management Instrumentation command line).

**Worm**: A self-replicating malware computer program that uses a computer network to send copies of itself to other systems **without human intervantion**. Usually it doesn't alter files, but it resides in active memory and duplicates itself. One example of it, is Botnet, monero, bondat, and beapy. Some worm makers: Internet Worm Maker Thing, Batch Worm Generator, and C++ Worm Generator.

---

<u>**Fileless Malware**</u>

Also known as **non-malware**, is a type of malicious software that uses legitimate programs to infect a computer. It does not rely on files and leaves no footprint, making it challenging to detect and remove.

Some examples of this type of malware are: Frodo, Number of the Beast, and The Dark Avenger. The last ones that came in the exam: Divergent (using registry for execution, persistence, and storage, and PowerShell to interject into other processes) and Duqu (making use of a TrueType font-related problem in win32k.sys).

This doesn't require *installation* of any code on a target's system and resides in RAM, using native, legitimate tools that are already part of the target system to execute attacks. 

The entry point is done through the same old methods: phishing e-mails, malicious websites, infected documents, malicious downloads, and links that look legitimate. 

<u>**Malware Analysis**</u>

It is the process of reverse engineering a piece of malicious software to discover important information about its makeup. Data points you'd be looking at in this effort include point of origin, how it actually works, what impact it might have from a growth perspective, and so forth.

There are two main methods of malware analysis - static and dynamic. *Static malware analysis* (aka *static code analysis*) is simply going through the executable code to understand the malware package. No code is executed and binaries are reviewed. There are 7 major techniques for performing static malware analysis:

- **File fingerprinting**: Simple process of computing a hash value for the code to identify it and compare for changes. Some tools:
  - HashMyFiles (https://www.nirsoft.net/utils/hash_my_files.html)
  - Mimikatz (https://github.com/ParrotSec/mimikatz)
  - MD5sums (https://www.pc-tools.net/win32/md5sums/)
- **Malware scanning (local and online)**: The use of anti-malware scanner.
- **Perform strings search**: Strings can be notes in the code from the programmer to denote what a particular section is doing, error messages  coded on, or specific items programmed in to communicate from the application to the user. Some tools to perform String searches: 
  - BinText (https://www.aldeid.com/wiki/BinText)
  - FLOSS 
  - Strings (https://learn.microsoft.com/es-es/sysinternals/downloads/strings)
- **Identify packing/obfuscation**: You can use tools like PEiD (https://www.aldeid.com/wiki/PEiD) to provide details about the executable, includng signatures for common packers, crypters, and compilers.
- **Identify portable executables (PE) information**: PE is the executable file format for Windows operating systems, encapsulating information necessary for Windows OS loaders to manage wrapped executable code. Some tools to analyze the metadata are:
  - PE.Explorer (https://www.heaventools.com/pe-explorer-es.htm)
  - PEView (https://www.aldeid.com/wiki/PEView)
  - Resource Hacker (https://www.angusj.com/resourcehacker/)
- **Identify file dependencies**: For any file to work, it has to interact with internal system files. Some tools:
  - Dependendy Walker (https://www.dependencywalker.com/)
  - Snyk (https://snyk.io/)
  - Dependency-check (https://jeremylong.github.io/DependencyCheck/): To find these import and export functions (in the kernel32.dll file), along with DLLs and library functions.
- **Malware disassembly**: Disassemblind the code to examine the assembly code instructions. IDA (https://hex-rays.com/ida-free) is a disassembler/debugger application that can help with this, providing information on funcion tracing, read/write executions, and instruction tracing.

More tools that helps identify malware:

- Hybrid Analysis (https://www.hybrid-analysis.com/)
- Jotti (https://virusscan.jotti.org/es-ES)
- Online Scanner (https://www.fortiguard.com/faq/onlinescanner)
- VirusTotal (https://www.virustotal.com/gui/home/upload)
- Volatility (https://volatilityfoundation.org/) -> Apart from analysis and forensic in general, they introduced the concept of analyzing the runtime state of a system using the data found in volatile storage (RAM).

---

*Dynamic malware analysis* is a bit different. The malware is put on an *sandbox* (isolated system) to execute it. People who do this, must be so cautious, dynamic is done only to analyze the behavior of the malware. Using a Virtual Machine with NIC in host-only mode and no open shares is a good start.

Several tools are used to check the behavior, before and after the execution, so you need to take a snapshot.We can check the change by analyzing ports (CurrPorts, Port Monitor and Process Explorer), network traffic (Capsa, SolarWinds NetFlow Traffic Analyzer), DNS (DNSstuff and DNSQuerySniffer), examining actual installation steps the malware uses (Mirekusoft Install Monitor and SysAnalyzer) and file and folder monitoring (Tripwire, Versisys and PA File Sight). Have a look at API monitor or APImetrics if you want to check calls allowing the malware to access system files.

<u>**Malware Countermeasures**</u>

To protect ourselves, we can use the tools mentioned earlier regarding, ports, network, system files and folder. 

It is recommendable to use a good anti-malware program and keep it updated. Malware move quickly in the modern world, and most of it runs and is kept in memory versus on the disk. Signatured-based AV simply can't keep up, and heuristic AV simply isn't much better.

> Emotet is a common banking Trojan (usually spread via a URL in an e-mail) that creates a file called cultureresource.exe, encrypts everything it tries to do, and communicates with a command-and-control external server. SamSam is well-known ransomware that uses brute-force tactics against RDP.

It is also suggested to use a *sheepdip* system, it is set up to check physical media, device drivers, and other files for malware before it is introduced to the network. It is isolated and configured with a couple of different AV programs, and other tools mentioned earlier to verify.

> Some words we should bear in mind. Terms such as *netizen* (aka cybercitizen: a person actively involved in online communities) and *technorati* (a blog search engine and an old, old term of endearment for aging techno-geeks).

---

## Remaining Attcks

<u>**Denial of Service**</u>

Seeks to to accomplish nothing more than taking down a system or simply denying access to it by authorized users. 

The *distributed denial-of-service (DDoS) attack*, comes not from one system but many, and they're usually part of a botnet. Remember that a *botnet* is a network of zombie computers the hacker can use to start a distributed attack from (examples of botnet software/Trojans are Shark and Poison Ivy). 

> Another way of saying "botnet" may be the *distributed reflection denial-of-service (DRDoS) attack*, also known as a *spoof attack*. It uses multiple intermediary machines to pull off the denial of service, by having the secondary machines send the attack at the behest of the attacker.

ECC lists 3 basic categories of DoS/DDoS: 
- *Volumetric attacks*: Consume bandwidth resources so the target cannot function. 
- *Protocol attacks*: Consume other types of resources, such as flooding SYN connection requests, fragmentation, or spoofed sessions.
- *Application layer attacks*: Aimed at specific application, consuming resources to render it kaput.

We'll list some examples of DoS/DDoS attacks:
- **TCP state-exhaustion attacks**: These attacks gp after load balancers, firewalls, and application servers by attemting to consume their connection state tables.
- **UDP flood**: Attacker spoof UDP packets at a high rate to random ports on the target, using a large source IP address range.
- **SYN attack**: The hacker sends thousands of SYN packets to the machine with a *false source IP address*. The machine attempts to respond with a SYN/ACK but will be unsuccessful (because the address is false). 
- **SYN flood**: The hacker sends thousands of SYN packets to the target but never responds to any of the return SYN/ACK packets. Because there is a certain amount of time the target must wait to receive an answer to the SYN/ACK, it will eventually bog down and run out of available connections.
- **ICMP flood**: The attacker sends ICMP Echo packets to the target with a spoofed (fake) source address. The target continues to respond to an address that doesn't exist and eventually reaches a limit of packets per second sent.
- **Smurf**: The attacker sends a large number of pings to the broadcast address of the subnet, with the source IP address spoofed to that of the target. The entire subnet then begins sending ping responses to the target, exhausting the resources there. A ***fraggle*** attack is similar but uses UDP for the same purposes.
- **Ping of death**: The attacker fragments an ICMP message to send to a target. When the fragments are reassembled, the resultant ICMP packet is larger than the maximum size and crashes the system. (This is not valid in modern systems, but is worthing to know)
- **Teardrop**: Attacker sends a large number of garbled IP fragments with overlapping, oversized payloads to the target machine. On older operating systems (such as Windows 3.1x, Windows 95, and Windows NT), this takes advantage of weaknesses in the fragment reassembly functionality of their TCP/IP stack, causing the system to crash or reboot.
- **Pulse wave**: The hacker sends highly repetitive and periodic groups of packets to the target on a regular basis (every ten minutes).
- **Zero day**: As the name indicates, this is a DDoS attack that takes advantage of a vulnerability before it is known and patched/mitigated by the target.
- **Permanent**: *Phlashing* refers to a DoS attack that causes permanent damage to a system. Usually this includes damage to the hardware and can also be known as *bricking* a system.

> Protocol attacks are measured in packets per second (pps), while Application layer attacks are measured in requests per second (rps).

Some tools to perform DoS on systems, such as:
- Low Orbit Ion Cannon (LOIC): is a simple-to-use DDoS tool that floods a targetwith TCP, UDP, or http requests. It was used in a coordinated attack against Sony's PlayStation network, and even got success against other companies, Recording Industry Associtation of America, Paypal, Mastercard, etc.
- Trinity:  Linux-based DDoS tool much like LOIC.
- Tribe Flood Network: Similar to others, using voluntary botnet systems to launch massive flood attacks on targets.
- R-U-Dead-Yet (RUDY): Performs DoS with HTTP POST via long-form flied submissions. 
- Slowloris: TCP DoS tool that ties up open sockets and causes services to hang. It's useful against web servers (at least Apache and others - Nginx isn't vulnerable to this) and doesn't consume large amounts of bandwidth (https://www.imperva.com/learn/ddos/slowloris/?redirect=Incapsula).

Regarding countermeasures against DoS attacks, actions such as disabling unnecessary services, using a good firewall policy, and keeping security patches and upgrades up to date are pretty standard fare. Additionally, the use of NIDS can help. Using tools like  Skydance can help detect and prevent DoS attacks.

> The real answer to a true DDoS is the involvement of your ISP up channel. It will be next to impossible for you, at an endpoint locale, to keep up with attacks from a sophisticated global (or even geographically close) botnet. The ISP may wind up blocking a lot of legitimate traffic, too, but it may be all you can do until the storm passes.

---

<u>**Session Hijacking**</u>

The idea is that the attacker waits for a session to begin and, after the authentication gets done, jumps in to steal the session for himself. This differs a little from spoofing attacks. 

In spoofing you're pretending to be someone else's address with the intent of sniffing their traffic while they work. *Session hijacking* refers to the active attempt to steal the entire session from the client. 

The steps for session hijacking are as follows:
1. Sniff the traffic between the client and the server
2. Monitor the traffic and predict the sequence numbering
3. Desynchronize the session with the client
4. Predict the session token and take over the session
5. Inject packets to the target

> Session hijacking can be done via brute force, calculation, or stealing. Additionally, you can always send a preconfigured session ID to the target; when the target clicks to open it, simply wait for authentication and jump in.

TCP session hijacking is possible because of the way TCP works. As a session-oriented protocol, it provides unique number to each packet, which allows the receiving machine to reassemble them in the correct, original order, even if they are received out of order.

The initial sequence number (ISN) is sent by the initiator of the session in the first step (SYN). This is acknowledged in the second handshake (SYN/ACK) by incrementing that ISN by one, and another ISN is generated by the recipient. This second number is acknowledged by the initiator in the third step (ACK), and from there on out communication can occur. The window size field tells the recipient how much data he can send before expecting a return acknowledgment.

> There are also windowing attacks for TCP that shrink the data size window.

![TCP Communication](https://ars.els-cdn.com/content/image/3-s2.0-B9781597491099500101-f06-03-9781597491099.jpg)

> You'll need to remember that the sequence numbers increment on acknowledgment. Additionally, you'll almost certainly get asked a scenario version of sequencenumbering (if I were writing the test, I'd give you one). You'll need to know, given an acknowledgment number and a windows size, what sequence number would be acceptable to the system. For example, an acknowledgment of 105 with a windows size of 200 means you could expect sequence numbering from 105 through 305.

There multiple tools to assist in session hijacking. 
- Ettercap: a packet sniffer on steroids, excellent MiTM tool and can be run from a variety of platforms.
- Hunt: can sniff, hijack, and reset connections at will.
- T-Sight: can easily hijack sessions as well as monitor additional network connections.
- Paros (known more as a proxy)
- Burp Suite
- Juggernaut (a well-known Linux-based tool)
- Hamster
- Ferret

> MITB attack (main-in-the-browser): occurs when the attacker sends a trojan to intercept browser calls. The Trojan basically sits between the browser and libraries, allowing a hacker to watch, and interact within, a browser session. 

Countermeasures for session hijacking:
- Use unpredictable session IDs
- Limiting incoming connections
- Minimizing remote access
- Regenerating the session key after authentication is complete
- Use encryption to protect the channel

**IPsec**: Protocol used to secure IP communication by providing encryption and authentication services to each packet. It works in two modes:
  - *Transport mode*
  - *Tunnel mode*

IPSec architecture includes the following protocols:
- Authentication Header: guarantees the integrity and authentication of the IP packet sender.
- Encapsulating Security Payload: ESP is a protocol that also provides origin authenticity and integrity, but it can take care of confidentiality too. ESP does not provide integrity and authentication for the entire IP packet in transport mode, but in tunnel mode it provides protection to the entire IP packet.
- Internet Key Exchage: IKE is a protocol that produces the keys for the encryption process.
- Oakley: uses Diffie-Hellman to create master and session keys.
- Internet Security Association Key Management Protocol: facilitates encrypted communication between two endpoints.

