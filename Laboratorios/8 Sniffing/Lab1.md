# Lab 1: Perform Active Sniffing

## Lab Objectives

* Perform MAC flooding using macof
* Perform a DHCP starvation attack using Yersinia

## Overview of Active Sniffing

Active sniffing involves sending out multiple network probes to identify access points. The following is the list of different active sniffing techniques:

**MAC Flooding**: Involves flooding the CAM table with fake MAC address and IP pairs until it is full

**DNS Poisoning**: Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not

**ARP Poisoning**: Involves constructing a large number of forged ARP request and reply packets to overload a switch

**DHCP Attacks**: Involves performing a DHCP starvation attack and a rogue DHCP server attack

**Switch port stealing**: Involves flooding the switch with forged gratuitous ARP packets with the target MAC address as the source

**Spoofing Attack**: Involves performing MAC spoofing, VLAN hopping, and STP attacks to steal sensitive information.

## Task 1: Perform MAC Flooding using macof

MAC flooding is a technique used to compromise the security of network switches that connect network segments or network devices. Attackers use the MAC flooding technique to force a switch to act as a hub, so they can easily sniff the traffic.

macof is a Unix and Linux tool that is a part of the dsniff collection. It floods the local network with random MAC addresses and IP addresses, causing some switches to fail and open in repeating mode, thereby facilitating sniffing. This tool floods the switch’s CAM tables (131,000 per minute) by sending forged MAC entries. When the MAC table fills up, the switch converts to a hub-like operation where an attacker can monitor the data being broadcast.

1. Entramos a ParrotOS y buscamos entrar a Wireshark
![alt text](image-1.png)

2. We choose the network interface that we want to analyze, in this case would be eth0.
![alt text](image-2.png)

3. At the same time, we launch a terminal with sudo root priviledge, and change our directory to root, an run the following command. 
```console
macof -i eth0 -n 10
```
This command will start flooding the CAM table with random MAC addresses, as shown in the screenshot.
> **-i**: specifies the interface and -n: specifies the number of packets to be sent (here, 10).

> You can also target a single system by issuing the command **macof -i eth0 -d [Target IP Address]** (-d: Specifies the destination IP address).

![alt text](image-3.png)

4. If we click on any packet IPv4, we will see information regarding MAC address, as the following screenshot.
![alt text](image-4.png)

5. Macof sends the packets with random MAC and IP addresses to all active machines in the local network. If you are using multiple targets, you will observe the same packets on all target machines.

6. This concludes the demonstration of how to perform MAC flooding using macof.
![alt text](image-5.png)

## Task 2: Perform a DHCP Starvation Attack using Yersinia

In a DHCP starvation attack, an attacker floods the DHCP server by sending a large number of DHCP requests and uses all available IP addresses that the DHCP server can issue. As a result, the server cannot issue any more IP addresses, leading to a Denial-of-Service (DoS) attack. Because of this issue, valid users cannot obtain or renew their IP addresses, and thus fail to access their network. This attack can be performed by using various tools such as Yersinia and Hyenae.

Yersinia is a network tool designed to take advantage of weaknesses in different network protocols such as DHCP. It pretends to be a solid framework for analyzing and testing the deployed networks and systems.

1. We will use Wireshark again, in the same interface. And we will leave it running.
![alt text](image-6.png)

2. We launch a terminal with sudo root priviledge, and change our directory to root, an run the following command.
```console
yersinia -I 
```
> **-I**: Starts an interactive session.
And the following screen will appear to us:
![alt text](image-7.png)

3. To remove the Notification window, press any key, and then press h for help. The Available commands option appears, as shown in the screenshot.
![alt text](image-8.png)
When we get familiarized, we can press **q** to quit the help list.

4. We will press **F2** to select DHCP mode. In that mode, **STP Fields** in the lower section of the window change to **DHCP Fields**, as shown in the screenshot.

5. After pressing **F2**, we will press **x** to see the following list attack options:
![alt text](image-9.png)

6. For our concerns, we will press **1** to start a DHCP starvation attack.

7. Yersinia starts sending DHCP packets to the network interface.
![alt text](image-10.png)

8. When we feel it is suffice, then we press **q**, to stop it.

9. Now we can go to Wireshark to see the DHCP packets, and see Ethernet section in packet details.
![alt text](image-11.png)

