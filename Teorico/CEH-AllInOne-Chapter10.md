# Chapter 10: Trojans and Other Attacks

## The "Malware" Attacks

*Malware* is fenerally defined as software designed to harm or secretly access a computer system without the owner's informed consent.

Some malware components definitions, the following list doesn't include every single variant in the malware world - some may use all or only some of the entire list :
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






