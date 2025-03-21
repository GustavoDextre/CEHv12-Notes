# Chapter 8: Mobile Communications and the IoT

## The Mobile World

**Mobile Vulnerabilities and Risks**

When it comes to smartphones, there are three main avenues to attack:
- The device itself
- Network attacks
- Data center or Cloud attacks

<br>

**OWASP Top 10 Mobile Risks**
<br>OWASP has an arm dedicated to mobile security, check this out (https://owasp.org/www-project-mobile-app-security/). We will go over each listed vulnerability, the current Top 10 (https://owasp.org/www-project-mobile-top-10/) includes the following vulnerabilities:

- **M1: Improper Patform Usage**: Misuse of a platform feature or failure to use platform security controls. It might be, Android intents, platform permissions, miuse of TouchID, the keychain, etc.
- **M2: Insecure Data Storage**: Threat agents include an adversary who has attained a lost/stolen mobile device as well as malware (or another repackaged app) acting on the adversary's behalf that executes on the mobile device.
- **M3: Insecure Communication**: Poor communication that could involve handshaking, SSL version, weak negotiation and clear-text communication; these could lead to phishing or MiTM attack.
- **M4: Insecure Authentication**: Involves failures regarding the user authentication and bad session management.
- **M5: Insufficient Cryptography**: Refers to the bad or poor implementation of cryptography to sensitive information asset.
- **M6: Insecure Authorization**: Failures in authorization (authorization decisions on the client side, forced browsing, and so on).
- **M7: Client Code Quality**: Problems in implementation of code in the client side. Encapsulate problems such as buffer overflows, format string vulnerability, and so on. The solution would be to rewrite some code that's running on the mobile device.
- **M8: Code Tampering**: Covers binary patching, local resource modification, method hooking, method swizzling, and dynamic memory modification. Resources located in the mobile after being installed, an attacker can modifiy it.
- **M9: Reverse Engineering**: Analysis of the final core binary to determine its source code, libraries, algorithms, and other assets. Useful tools such as IDA Pro, Hopper, otool, etc. 
- **M10: Extraneous Functionality**: These are never intented to be released into a production environment, but they usually pop up in the weirdest places. Examples of inclding password in a comment in the source code or forgetting to turn on the MFA.

---

**Rooting and Jailbreaking**
<br>Those terms means the same: perform some action that grants you administrative (root) access to the device.

- Rooting -> For Android devices, we'll list some tools:
  - KingoRoot (https://www.kingoapp.com/)
  - TunesGo
  - OneClickRoot (https://oneclickroot.com/)
  - MTK Droid (https://androidmtk.com/)
- Jailbreaking -> For iOS devices **(invalidates every warranty you can think of)**, we'll list some tools:
  - Cydia (https://www.cydiafree.com/)
  - Hexxa Plus (https://pangu8.com/jailbreak/12-3/)
  - Apricot (https://pangu8.com/review/apricot/)
  - Yuxigon (https://yuxigon.com/)

There are 3 basic techniques:
- **Untethered jailbreaking**: The kernel remains patched after reboot, with or without a system connection.
- **Semi-tethered jailbreaking**: A reboot no longer retains the patched kernel; the software was added and if admin priviledge needed , the installed jailbreaking tool can be used.
- **Tethered jailbreaking**: A reboot removes all jailbreaking patches, the device may get stuck in a perpetual loop on startup, requiring a system connection (USB) to repair.

And 3 types of jailbreaking:
- **Userland exploit**: Found in system itself, which is leveraged to gain root access, to modify the fstab, and patch kernel. Cannot be tethered, it can be patched by Apple. **This exploit provides user-level access but not admin**.
- **iBoot exploit**: Found in one of the device's bootloaders, called iBoot (the other bootloaders are called SecureROM and LLB). Can be semi-tethered, and they can be patched by Apple.
- **BootROM exploit**: Allows access to the file system, iBoot, and custom boot logos, and is found in the device's first bootloader, SecureROM. Can be untethered, but cannot be patched by Apple: it's hardware, not software.

<br>

> Android's Device Administration API (https://developer.android.com/work/device-admin?hl=es-419) provides system-level device administration. You can create "security-aware" apps that may prove useful within your organization.

**BYOD**: means "Bring Your Own Device", allows companies to take advantages, for free, of all that computing power we're all walking around with our hands. The problem with this, is the security control (or the lack thereof by organizations). 

**MDM**: means "Mobile Device Management" is to add some control to enterprise mobile devices, similar to Group Policy in Windows. MDM helps in pushing security policies, application deployment, and monitoring of mobile devices; offers passcodes, unlocking, remote locking, remote wipe, root or jailbreaking detection, etc. Some solutions: Citrix XenMobile, IBM Security MaaS360, and SOTI MobiControl.

Both, BYOD and MDM get success only when policies are established and supported. 

---

Bluetooth refers to an open wireless technology for short range (10 meters or less). It is so susceptible to hacking what makes ot so ubiquitous. 
<br>
Bluetooth has two modes:
- Discovery Mode: determines how the device reacts to inquiries from other devices looking to connect, and it has three actions:
  - **Discoverable**: action obviously has the device answer to all inquiries.
  - **Limited discoverable**: Restricts that action.
  - **Nondiscoverable**: To ignore all the inquiries.

- Pairing Mode: how the the device reacts when another Bluetooth system asks to pair with it. There are two versions:
  - **Pairable**: They will pair each other. Accepts all connection requests.
  - **Nonpairable**: No, they won't. Rejects every connection request.

> We should not assume that Bluetooth is insecure because of its "pairable mode"; in fact, the truth is quite the opposite. Bluetooth, tends to differentiate between discoverability, connectability, and pairability, so while the opportunity to connect may exist, it's not simply an open connection.

---

**Mobile Attacks**
<br>Attacks on mobile devices abound.
- Smishing (phishing by SMS)
- Some list of Trojans:
  - TeaBot
  - FakeInst
  - OpFake
  - Boxer
  - KungFu
- Spyware:
  - Mobile Spy
  - SPYERA
- Google Voice (can be us against to us)
- Tracking user tools:
  - AndroidLost
  - Find My Phone
  - Where's My Droid

And how about using our mobile as an attack platform? Some tools:
- Network Spoofer (helps you control how website appear on a desktop/laptop)
- DroidSheep (used to perform sidejacking, by listening wireless packets and pulling session IDs)
- Nmap
- Kali Linux
- **NetCut** (https://arcai.com/netcut/) you can disconnect users you don't like.

Now that we talked about Bluetooth earlier, we can list some attacks against it:
- **Bluesmacking**: DDoS attack against the device
- **Bluejacking**: Sending unsolicited messages to, and from, mobile devices.
- **Bluesniffing**: Effort to discover Bluetooth-enabled device-similar to wardriving in WiFi.
- **Bluebugging**: Successfully accessing a Bluetooth-enabled device and remotely using its features.
- **Bluesnarfing**: Theft of data from a mobile device due to an open connection - such as remaining in discoverable mode.
- **Blueprinting**: Involves collecting device information over Bluetooth (we can think similar to footprinting).

Some tools for Bluetooth:
- BlueScanner: find devices around us, and it will try to extract and display as much information as possible.
- BT Browser: Useful as well for finding and enumerating nerby devices
- Bluesniff and bt Crawler: provides GUI
- Blooover: Good choice for bluebugging
- **Super Bluetooth Hack**: all-in-one software that allows us to do almost anything in a device we're lucky enough to connect to. If it is smartphone, you can read all messages, contacts, change profiles, restart the device, make calls, etc.
---

## IOT
IoT refers to a network of devices with IP addresses that have the capability of sensing, collecting, and sending data *to each other*. Extends internet connection beyond *standard* devices such as desktops, laptops and smartphones, to any range of traditionally non-network-enabled physical dvices and *everyday objects*. The IoT has taken that to a whole new level by making everything internetworked.

<u>**IoT Architecture**</u>
<br>How IoT works comes down to three basic components: 
- **Sensing Technology**
- **IoT gateways**
- **Cloud** (data storage availability)

A thing inside the IoT is defined as any device implanted somewhere that has the capability of communicating on the network. Each IoT device is embedded with some form of sensing technology, can communicate and interact over the Internet, and oftentimes can be remotely monitored and controlled.

> One example in IoT is "maybe we should slow this turnover of all functions to the machines" -> (https://www.nytimes.com/2016/01/14/fashion/nest-thermostat-glitch-battery-dies-software-freeze.html)

Some items makes these to interact with each other. The first to mention is the **operating system** allowing all data collection and analysis in the first place.
- **RIOT OS**: It can run on embedded systems, actuator boards, and sensors, uses energy efficiently, and has very small resource requirements.
- **ARM mbed OS**: This is mostly used on wearables and other devices that are low-powered.
- **RealSense OS X**: Intel's depth-sensing version, this is mostly found in cameras and other sensors.
- **Nucleus RTOS**: This is primarily used in aerospace, medical, and industrial applications.
- **Brillo**: An Android-based OS, this is generally found in thermostats.
- **Contiki**: This is another OS made for low-power devices; however, it is found mostly in street lightning and sound monitoring.
- **Zephyr**: Another option for low-power devices and devices without many resources.
- **Ubuntu Core**: This is used in robots and drones, and is also known as "snappy".
- **Integrity RTOS**: This is primarily found in aerospace and medical, denfense, industrial, and automotive sectors.
- **Apache Mynewt**: Devices using Bluetooth Low Energy Protocol make use of this.

Devices needs to communicate, mostly done over wireless, and it is done by one of the 4 IoT communication models:
- Device to Device: communicates directly with each other
- Device to gateway: adds a collective (aka a gateway device) before sending to a cloud, which can be used to offer some security controls.
  ![Example of device to gateway](https://www.mouser.hn/blog/Portals/11/Bhatt_Gateways%20Secure%20IoT%20Architectures_Theme%20Image_Figure%201.png)
- Device to cloud: communicates directly with each other
- Back-end data sharing: similar to device to cloud; however, it adds the ability for third parties to collect and use the data.

> Vehicle Ad Hoc Network (VANET) is the communications network used by our *vehicles*. It refers to the spontaneous creation of a wireless network for vehicle-to-vehicle (V2V) data exchange.

We will list some architecture layers inside IoT: 
- **Edge Technology Layer**: Consists of sensors, RFID tags, readers, and the devices themselves.
- **Access Gateway Layer**: First data handling takes place in this layer, with message identification and routing occuring here.
- **Internet Layer**: Crucial layer, as it serves as the main component to allow all communication.
- **Middleware Layer**: This layer sits between the application and hardware layers, and handles data and device management, data analysis, and aggregation.
- **Application Layer**: This layer is responsible for delivery of services and data to user.

> Useful information regarding IoT: From IEEE (https://ieeexplore.ieee.org/xpl/RecentIssue.jsp?punumber=6488907) and ITU (https://www.itu.int/en/ITU-T/ssc/resources/Pages/topic-001.aspx)

<u>**IoT Vulnerabilities and Attacks**</u>
<br>OWASP Top 10 is present in IoT as well (https://wiki.owasp.org/index.php/OWASP_Internet_of_Things_Project#tab=IoT_Top_10). We'll list the Top 10:
- **I1: Weak, Guessable. or Hardcoded Passwords**: Use of easily bruteforced, public, or unchangeable credentials, including backdoors in firmware or client software that grants unauthorized access to deployed systems.
- **I2: Insecure Network Services**: Using unnecessary services running, that are exposed to internet, and can compromise CIA or allow unathorized remote control.
- **I3: Insecure Ecosystem Interfaces**: Insecure services outside of the device that allows compromise of itself and its components. Includes issues like: lack of authentication/authorization, weak encryption, input and output filtering.
- **I4: Lack of Secure Update Mechanism**: Lack of ability to securely update the device. Such as: lack of firmware validation on device, lack of secure delivery, lack of anti-rollback mechanisms, etc.
- **I5: Use of Insecure or Outdated Components**: Use of deprecated or insecure software that could allow the device to be compromised. Customization of OS platforms, use of 3rd-party software or hardware components from a compromised supply chain.
- **I6: Insufficient Privacy Protection**: The information of users are stored on devices that is used insecurely, improperly or without permission.
- **I7: Insecure Data Transfer and Storage**: Lack of encryption or access control sensitive data , including at rest, in transit, or during processing.
- **I8: Lack of Device Management**: Lack of security support on devices deployed in production, including assets management, updating, decommissioning, monitoring, and response capabilities.
- **I9: Insecure Default Settings**: Leave the system with default settings.
- **I10: Lack of Physical Hardening**: Allows potential attackers to gain sensitive information that can help in a future remote attack or take local control of the device.

To know more about the OWASP Project: https://owasp.org/www-project-internet-of-things/

> EC Council considers as well OWASP IoT Attack Surface Areas (https://wiki.owasp.org/index.php/OWASP_Internet_of_Things_Project#tab=IoT_Attack_Surface_Areas), which in total there are 18 attack surface areas.

Examples of some IoT attacks:
- DDoS:  It can be carry out similar to DDoS from any other device. One version is the *sybil* attack, multiple forged identities are used to create the illusion of traffic congestion that affects everyone else in the local IoT network.
- Rolling Code: The code used by key fob to unlock start a car is called *rolling* (or *hopping*) code. This attack can sniff for the first part of the code, jam the key fob, and sniff/copy the second part on the subsequent attempts, allowing the attacker to steal the code, and the car. You can use HackRF One (https://greatscottgadgets.com/hackrf/) to pull this off.
- BlueBorne: Amalgamation of techniques and attacks against known, Bluetooth vulnerabilities.
- Malware --> e.g. Mirai 
- Ransomware
- MiTM
- HVAC -> Shut down air conditioning services
- Fault Injection (aka Perturbation): A malicious actor injects a faulty signal into the system. There are four types:
  - Optical, EMFI (Electromagnet fault injection) or Body Bias Injection (BBI; using laser or electromagnetic pulses)
  - Power or Clock glitching (affecting power supply or clock)
  - Frequency or voltage tampering (tampering with operating conditions themselves)
  - Temperature attacks (altering temprature for the chip)

<u>**IoT Hacking Methodology**</u>
<br>The steps look so similar to the EC Council standard:
1. **Information Gathering**: Reconnaissance and footprinting for IoT devices. It is often used *Shodan* (https://www.shodan.io) which is a search engine to find *everything*, devices connected to the internet.
> Shodan requires registraron, it is highly recommended to hide as much as possible our identity; considering using TOR on a USB, create a fake e-mail account, and registrate with it.
2. **Vulnerability Scanning**: Regarding IoT, there are som tools to mention:
   - Nmap
   - beSTORM (from Beyond Trust, https://www.beyondsecurity.com/bestorm.html)
   - IoTsploit (https://iotsploit.co)
   - IoT Inspector (https://www.iot-inspector.com)
3. **Launching Attacks**: We'll mention some tools:
   - Firmalyzer (https://firmalyzer.com) -> for performing active security assessments on IoT devices.
   - KillerBee (https://github.com/riverloopsec/killerbee)
   - JTAGulator (https://www.grandideastudio.com/jtagulator/)
   - Attify Zigbee Framework (https://github.com/attify/Attify-Zigbee-Framework) -> provides a suite of tools for testing Zigbee devices.
4. **Gaining Access** (e.g. using telnet is often in IoT)
5. **Maintaining Access** (e.g. using telnet is often in IoT)

> Some other tools for Information gathering: Censys (https://censys.io) and Thingful (https://www.thingful.net).

To finish, it is also worthy to mention some defense mitigations suggested:
- Removing unused accounts (guest and demo accounts) and services (Telnet)
- Implementing IDS/IPS
- Use of built-in lockout features
- Encryption (e.g. VPN and strong authentication)
- Disabling UPnP ports on routers
- Monitoring traffic on port 48011 (commonly used for malicious traffic)
- Catching up with patching and firmware updates
- Use of DMZ zones for network segmentation and traffic control

> Sniffer fot IoT traffic: Foren6 (https://cetic.github.io/foren6/) "leverages passive sniffer to reconstructs information from the network to support real-world Internet of Things applications where other means of debug (cabled or network-based monitoring) are too costly or impractical. Another sniffer to mention is CloudShark (https://www.qacafe.com/analysis-tools/cloudshark)

---

## OT Hacking

It is defined by Gartner and NIST, as a "hardware and software that detects or causes a change through the direct monitoring and/or control of physical devices, processes and events in the enterprise". OT is everywhere around us: in factories, utilities, oil and gas system, and transportation, temperature controls, etc.

Architecture of OT consists of several subsets, some of them are:
- Supervisory control and data acquisition (SCADA)
- Industrial control systems (ICS)
- Remote Terminal Units (RTU)

Some terms to get familiarized with and to memorize:
- **Assets**: Physical and logical assets making up an OT system. 
- **Zones** (aka **conduits**): These are network segmentation techniques.
- **Industrial Network**: A network consisting of automated control systems.
- **Business network**: Systems offering information infrastructure to the business.
- **Industrial Protocols**: Include both serial and Ethernet communication protocols (like S7, CDA, CIP, etc).
- **Perimeter**: It consists of, the network (a closed group of assets inside a boundary) or the electronic security perimeter (boundary between secure and insecure zones).
- **Critical Infrastructure**: Physical and logical systems that must be protected, as harm or destruction could cause severe impact to safety, economy, or public health. 

> **IIOT** -> the convergence of IoT and OT to bridge gaps between them. This allows for, and largely pushed into existence, Industry 4.0, bringing "smart manufacturing" and IoT applications into industrial operations.

OT architecture is generally discussed and examined within something called the **Purdue Model**. The Purdue Enterprise Reference Architecture (PERA) is still widely usedblueprint for discussing and evaluating OT. It consists of 3 zones:
- Manufacturing Zone (OT)
- Enterprise Zone (IT)
- Demilitarized Zone (DMZ) -> also known as the Industrial Demilitarized Zone (IDMZ)

![Purdue Model example](https://www.researchgate.net/publication/349195440/figure/fig1/AS:989863574790163@1613013275868/CS-Purdue-Model-architecture.png)

> Industrial Control System (ICS) can be controlled in three main models: 
> <br>**One loop**: Are independent of the desired output (not measured and compared). Operates without any checks and balances and are expected to follow input commands regardless of the final result.
> <br>**Closed loop**: Has the control action entirely dependent on the desired output. They measure, monitor and control the process using feedback to compare actual versus desired output.
> <br>**Manual**: Rely on operator input.

ICS architecture is a collection of different control systems (like SCADA, BPCS, RTU, and DCS systems) as well as their associated equipment and control mechanisms. ICS is usually seen in known activities, such as electricity, water and transportation of materials, gas or oil.

**Distributed Control System (DCS)**: Large-scale, highly engineered system containing (usually) a central supervisory control unit and multiple input/output points that is used to control specific industry tasks. 

**SCADA**: Centralized supervisory control system generally used for ocntrolling and monitoring industrial facilities and infrastructure. Consists of a control server (SCADA-MTU), communications devices, and distributed field sites (used to monitor and control specific operations).

    Other acronyms to get to know:
    PLC (Programmable logic controller)
    BPCS (Basic process control system)
    SIS (Safety instrumented systems)

<u>**Security Concerns**</u>
<br>There is methodology hacking for OT. However, it is the same that it was showed earlier:

- Information gathering -> Shodan to get e.g. SCADA. We can use CRITIFENCE (https://www.critifence.com/critifence/) to find default passwords of SCADA.
- Vulnerability Scanning -> scanning example: **nmap -Pn -sT -p 502 -script modbus-discover <*target IP*>**
- Launching Attacks
- Gaining Remote Access
- Maintaining Access

> Schneider Electric is a big player in the PLC realm, and Modbus is a data communications protocol they use within their PLCs. If you seach in Shodan for either Modbus, Schneider Electirc, or both (maybe with geographic operator) might show you a world of SCADA very close by.

Some debug tools worthing to mention:
- GDB (https://www.gnu.org/software/gdb)
- Radare2 (https://github.com/radareorg/radare2)
- OpenOCD (https://openocd.org/)
- IDA Pro (https://hex-rays.com/)
- Mestasploit (e.g. can be used for Modbus)
- modbus-cli (https://github.com/tallakt/modbus-cli): Modbus master and slave communicate in plain text with no authentication. After identifying PLCs connected to the Internet, install modbus-cli and fire away. 

> Modbus has announced they are replacing the term "master-slave" with "client-server"
