# Chapter 7: Wireless Network Hacking

**Wireless Data World** --> Use standards for communication 802.11 series.

    Modulation:
    * The practice of manipulating properties of a waveform. 
    * There are endless methods, but we mostly focus on OFDM and DSSS.
  
| Wireless standard                                                                                                                       | Operating Speed (Mbps) | Frequency (GHz)   | Modulation Type           |
| --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ----------------- | ------------------------- |
| 802.11a                                                                                                                                 | 54                     | 5                 | OFDM                      |
| 802.11b                                                                                                                                 | 11                     | 2.4               | DSSS                      |
| 802.11d       | variation of a and b standards for global use (allowing variations for power, bandwidth and so on). |||
| 802.11e    | QoS iniative providing guidance for data and voice prioritization. |||
| 802.11g                                                                                                                                 | 54                     | 2.4               | OFDM and DSSS             |
| 802.11i    | WPA/WPA2 encryption standards   |||
| 802.11n                                                                                                                                 | 100+                   | 2.4 - 5           | OFDM                      |
| 802.15.1 (Bluetooth)                                                                                                                    | 25 - 50                | 2.4               | GFSK, 8DPSK, $\pi$/4-DPSK |
| 802.15.4 (Zigbee)                                                                                                                       | 0.02, 0.04, 0.025      | 0.868, 0.915, 2.4 | O-QPSK, GFSK, BPSK        |
| 802.16 (WiMAX)                                                                                                                          | 34 - 1000              | 2 - 11            | SOFDMA                    |

---
**OFDM (Orthogonal Frequency-division multiplexing)**
: The transmission media is divided into a series of frequency bands that do not overlap each other, and each each of them can be then used to carry a separate signal.

**DSSS (Direct-sequence spread spectrum)**
: Works by combining all the available waveforms into a single purpose. The entire frequency bandwidth can be used at once for the delivery of a message.

---

# Wireless Network 
Operates in two ways:

    Ad-hoc
    ------ 
    Connects directly to another system, as if a cable were strung between the two. (not often seen)

    Infrastructure 
    --------------
    (MOST USED) Makes use of an Access Point (AP) to funnel all wireless connection through.

**AP** is set up to connect with a link to the outside world (usually some kind of broadband network).

- Clients connect to it by NIC (Network Interface Card).
- Its footprint is Basic Service Area (BSA).
- Communication with its clients is **Basic Serice Set (BSS)**.
- Using multiple APs in the same channel is **Extended Service Set (ESS).**
-  **BSSID** is the MAC Address of the AP, that is at the center  of the BSS.

**TIP** : A spectrum analyzer can be used to verify wireless quality, detect rogue access point, and detect various attacks against your network.

    SSID (Service Set Identifier)
    -----------------------------
    - 32 characters or less
    - it serves to identify the network, no provides any security.
    - It is broadcast by default and are easily obtainable even if it is turned off.

# Wireless Authentication

## 1. Open System Authentication
![Open System Authentication](/assets/Open%20System%20Authentication.png)

## 2. Shared Key Authentication
![Shared Key Authentication](/assets/Shared%20Key%20Authentication.png)

## 3. Centralized Authentication
![Centralized Authentication](/assets/Centralized%20Authentication.png)

---
    Association
    -----------
    The action of a client connecting to an AP.

    Authentication
    --------------
    Identifies the client before it can access anything on the network.
---

# Wiresless Encryption

## 1. WEP (Wireless Equivalent Privacy)
- Does not encrypt anything
- It was not intented to fuklly protect your data
- It was designed to give people using a wireless network the same level of protection someone surfing over an Ethernet Wired Hub.

## 2. WPA (Wi-Fi Protected Access)
- Use Temporal key Integrity Protocol (**TKIP**), 128-bit key and the client's MAC Address to accomplish much stronger encryption.
- Change the Key every 10,000 packets, instead of reusing as WEP does.
- Keys are transfered back and forth during an **Extensible Authentication Protocol (EAP)** authentication session, 4-step handshake to prove the client belongs to the AP and viceversa.

## 3. WPA2 
- Similar to WPA.
- It was designed with the government and the enterprise in mind.
- WPA2 personal, much like other encryption offerings, simply set up a pre-shared key and give it only to those people you trust on your network.
- Uses AES for encryption, ensuring FIPS 140-2 Compliance.
- TKIP has some irregularities, WPA2 addresses these by using **Cipher Block Chaining Message Authentication Code Protocol (CCMP)**, it uses something to show that the has not been altered during transit. It is a hash, but CCMP call it **Message Integrity Code (MIC)**, and the entire process, is accomplished through **Cipher Block Chaining Message Authentication Code  (CBC-MAC)**.
- The way to crack WPA2 is to use a tool that creates the crypto key based on the password.
- You must capture the authentication handshake used in WPA2 and attempt to crack the **Pairwise Master Key (PMK)** from inside *(tools such as AirCrack and KisMAC)*.

## 4. WP3 
Uses AES-GCMP-256 for encryption and HAMC-SHA-384 for authentication.

### Personal
- Use Dragonfly Key Exchange to deliver password-based authentication through SAE.
- It is resistant to offline and key recovery attacks. 

### Enterprise
- Uses multiple encryption algorithms to protect data and employs ECDSA-384 for exchanging keys.

---

| Wireless Standard | Encryption Used | IV Sized (Bits) | Keys Length (Bits) | Integrity Check | 
|---|---|---|---|---|
| WEP | RC4 | 24 | 40 / 104 | CRC-32 | 
| WPA | RC4 + TKIP| 48 | 128 | Michael Algorithm + CRC-32 | 
| WPA2 | AES + CCMP | 48 | 128 | CBC-MAC (CCMP) | 
---
**WEP** --> Susceptible to plain texts attacks. Password attacks is easy to pull off.

**WPA** --> Pre-shared key is vulnerable to eavesdropping and offline attack, and its TKIP  function is vulnerable to packet spoofing.

**WPA2** --> Has the same Pre-shaed key issues like WPA, and the so-called Hole 196 vulnerability makes it vulnerable to man in the middle attack and DoS (Denial of Services).

# Wireless Hacking 

## Threats
- Access control attacks
- Integrity attacks
- Confidentiality attacks
- Availability attacks
- Authentication attacks

**WiGLE**
- To find wireless networks and to get a glimpse into someone's smartphone 
- Use NetStumbler in cars, with antenna and GPS.

### Network Discovery 
**War Options**: Attacker travels around with a Wi-Fi enabled device looking for open wireless access point.

- War driving: In a car
- War walking: On foot
- War flying: In a aireplane
- War chalking: Different concept, it is related to using symbols to indicate network availability.

### Wireless Adapters
- To pull the frames out of the air.
- Tools:
  - AirPcap dongle USB: To capture data, management and control frames, works well with Aircracking.
  - Other tools: metageek's eye P.A. 112 and Acrylic Wi-Fi sniffer.
  - NetStumbler: Windows-based, compatible with 802.11a, b and g.
  - Kismet: Linux-based, works passively *(Means it detects access points and clients without activally sending any packets).*
    - It can detect access points that have not been configured (and would then be susceptible to the default out-of-the-box admin password).
    - Works by channel hopping,, to discover as many networks as possible.
    - It has the ability to sniff packets and save them to a log file, readable by wireshark ot tcpdump.

### Attacks

- **Evil twin**
  - Assuming the SSID on the rogue box is set similar to the legitimate one.
  - It is easy to pull of.
  - Misassociation attack (may also be referenced).
  - Additionally, faking a well-known hotspot on a rogue AP is referred to as a **honeyspot attack**, or **aLTEr attack**, placing a virtual tower between two LTE  devices and hijacking the session.
<br ><br>
> Cisco is among the leaders in rogue access point detection technologies. Many of its access points can be configured to look for other access point in the same area. If they find one, they send SNMP or other messages back to administrators for action, if needed.
<br >
- **Ad Hoc connection Attack**
  - Occurs when attacker sits down with a laptop somewhere in your building and advertises and ad hoc network from his laptop, and people start connecting.

- **Denial of Service**
  - Use a number of tools to craft and send de-authenticate (disassociate) packets to clients of an AP, which will force them to drop their connections. They will try to connect again and you might leverage to put a rogue AP.
  - Removing access to legitimate networked resources (unathorized association).
  - Jam the wireless signal altogether, using some type of jamming devices and, usually, high-gain antenna amplifier. Anything generating enough signals in the 2.4GHz range would definitely put a crimp in an 802.11b network.
<br ><br>

> Messing around with jammers is a really good way to find yourself in hot water with the Federal Communications Commission (FCC).

<br >

Some network administrators attempt to enforce a MAC filter, based on a MAC address list, that are allowed to associate to the AP. However, this measure can be useless if we using spoofing our MAC address *(tools like SMAC or TMAC, or simply commands)*.

```bash
ifconfig wlan0 down
ifconfig wlan0 hw ether 0A:15:DB:1A:1B:1C
ifconfig waln0 up
```

### <u>Wireless Encryption Attacks</u>

**Cracking WEP**

- Generate enough packets to get the encryption key.
- Using AirCrack-ng
  - Provides: Sniffer, wireless netowrk detector, a password cracker, and even a traffic analysis tool and can run on Windows or Linux.
  - For WEP: can use a dictionary attack or algorithmic processes called PTW, FMS and the korek technique.
<br ><br>
> <u>AirCrack-ng</u>
  <br> May use dictionary for cracking WPA and WPA2, the other techniques is for WEP.

> <u>Cain and Abel</u>
  <br> Just sniffing packets and cracking as stated earlier, but it may take a little longer than other ones. Relies on statistical measures and PTW technique to break WPE codes.

> <u>KISMAC</u>
  <br> (A MacOS application) can be used to brute-force to WEP or WPA password.

Other tools like WPEAttack, WPECrack, Secpoint Portable Penetrator (for mobile) and Elcomsoft Wireless Security Auditor.

---
Another method of attack:

**Key Reinstallation Attack (aka KRAck)**
- Replay attack that takes advantage of the way WPA2 works.
- A couple of Belgian researches discovered that by repeatedly resetting and replaying a portion of traffic, they could eventually learn the full key used to encrypt all traffic.
- The reasearches targeted WPA2's use of a four-way hadnshake to establish a nonce an one-time-use shared secret for communication session.
- WPA2 allows reconnection using the same value for the third handshake.
- WPA2 use a one-time-use key for reconnection, attacker send repeatedly the third handshake of another device's session to manipulate or reset the WAP2 encryption key.
- Each time this key is reset, the reset causes data to be encrypted using the same values.
- The attacker can match encrypted packets seen and by the time, learn the full key chain used to encrypt the traffic.

### <u>Wireless Sniffing</u>

Tools:
- Omnipeck: Used in promiscuous mode, network activity status and monitoring.
- Airemagnet: Reporting engine that maps network information to requirements for compliance with policy and industry regulations.

