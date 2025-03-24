# Chapter 9: Security in Cloud Computing

## Cloud Computing

Cloud computing provides individual and enterprise subscribers on-demand delivery of various IT services as metered services over a network. Cloud computing offers everything from on-demand self-service, storgae, and resource pooling to elasticity, automation in management, and broad network access.

<u>**Cloud Computing Service Types**</u>

1. *Infrastructure as a Service (IaaS)*: A third-party provider hosts infrastructure components, applications, and services on behalf of its subscribers, with a *hypervisor* (VMWare, Oracle VirtualBox, Xen or KVM) running the virtual machines as guests. It is a good choice for day-to-day infrasctructure and temporary or experimental workloads that may change unexpectedly. Subscribers only pay for resources used.
2. *Platform as a Service (PaaS)*: it is geared toward software development. Hardware and software are hosted by the provider on its own infrastructure.
3. *Software as a Service (SaaS)*: It is simply a software distribution effort. The total responsability is now in the court of the provider, even regarding secuirty of this software. Includes easier administration, automated patch management, compatibility, and version control.

![Image of Cloud Computing models](https://miro.medium.com/v2/resize:fit:1400/1*ymeDRVo9Wuf9qCmRebC-Ew.png)

Other, lesser-known cloud computing service types include the following:

- **Identity as a Service (IDaaS)**: services on the identity and access management (IAM). Examples such as Microsoft Azure Active Directory and Centrify's Identity Service.
- **Function as a Service (FaaS)**: platform used for developing, managing, and running application functionalities (modular pieces of code that needs to work on the fly, and are usually executed in response to certain events). Examples such as AWS Lambda and Google Cloud Functions.
- **Security as a Service (SECaaS)**: Provides a suite of actions , such as intrusion detection, incident management, anti-malware, and pentesting. Examples such as McAfee Managed Security Systems, and eSentire MDR.
- **Container as a Service (CaaS)**: Virtualizes container engines and provides management through a web portal. Examples such as Amazon Elastic Compute Cloud (EC2) and Google Kubernetes Engine (GKE).

---

**Container**: It is basically a package holding components of a single application and all its dependencies, relying on virtual isolation to deploy and run that application. 

A good article to read is: https://www.techtarget.com/searchsecurity/feature/What-are-cloud-containers-and-how-do-they-work

> Multiple cloud vendors offer CaaS, such as Aamazon Elastic Container Service (ECS), Google Kubernetes Engine, and Microsoft Azure Container Instances (ACI). 

Containers are designed to virtualize a single application, not an OS (this is for VMs). Regarding containers, the leader is Docker (https://www.docker.com), in 2013, Docker Engine was launched to work on any Linux distro, Windows; and to run applications anywhere consistently on any infrastructure, solving 'dependency hell'.

It is worth to mention Kubernetes, aka "K8". It's an open source container management platform, developed by Google in the hands of Cloud Native Computing Foundation (CNCF), designed to run accress clusters (whereas Docker is designed for a single system). 

> Docker architecture uses something called the Container Network Model (CNM) to connect containers and hosts.

> Docker's container management in cluster form is called "docker swarm".

---

<u>**Cloud Deployment Models**</u>

There are 4 main cloud deployment models:

- **Public Cloud Model**: Services provided over a network that is open for public use (like the Internet). Security and compliance requirements aren't a major issue.
- **Private Cloud Model**: Operated solely for a single organization (aka **single-tenant environment**), and is usually not a pay-as-you-go operation. Preferred by larger organizations, because hardware is dedicated and security and compliance reqs can be easily met.
- **Community Cloud Model**: Cloud infrastructure shared by several organizations, usually with the same policy and compliance considerations. 
- **Hybrid Cloud Model**: A composition of two or more cloud deployment models.

> A relatively new term is "multi-cloud". This deployment model combines workloads across multiple cloud providers in ine heterogeneous environment. To know more, read this: https://www.vmware.com/topics/hybrid-cloud-vs-multi-cloud

---

**NIST Cloud Computing Reference Architecture**

It is worthing to talk about U.S. government rules and regulations regarding the cloud. NIST released Special Publication (SP) 500-292, *NIST Cloud Computing Reference Architecture* (https://www.nist.gov/customcf/get_pdf.cfm?pub_id=909505), we will highlight the five major roles within this cloud architecture:
- **Cloud Carrier**: The organization that has the responsability of transferring the data. It is the intermediary for connectivity and transport between subscriber and provider.
- **Cloud Consumer**: The individual or organization that acquires and uses cloud products and services.
- **Cloud Provider**: The purveyor of products and services.
- **Cloud Broker**: Acts to manage use, performance, and delivery of cloud services, as well as the relationship between providers and subscribers. The broker acts as the intermediate between consumer and provider and will help consumers through the complexity of cloud service offerings and may also create value-added cloud services as well.
- **Cloud Auditor**: Independent assessor of cloud service and security controls. The auditor "provides a valuable inherent function for the government by conducting the independent performance and security monitoring of cloud services".

![NIST Cloud Computing Reference Architecture](https://cloudgal42.com/wp-content/uploads/2021/05/nistccra.png)

Other regulatories bodies to mention: FedRAMP, PCI DSS and FIPS. 

Cloud Security Alliance (CSA) promotes best security practices and organizing cloud security professionals. CSA published gobs of documentation  on everything from privacy concerns to security controls' focus and implementation (https://cloudsecurityalliance.org/).

## Cloud Security

When it comes to cloud security, as we know the cloud is kind of services that is delivered by a provider. We must be concerned with the security of the provider as well as that of the subscriber, and *both* are responsible for it.

> *Trusted Model Computing* refers to an attempt to resolve computer security problems through hardware enhacements and associated software modifcations. The Trusted Computing Group (TCG) is made up of a bunch of hardware and software providers who cooperate to come up with specific plans. Something called *Roots of Trust (RoT)* is a set of functions within the Trusted Computing Model that are always trusted by the computer's operating system.

CSA and ECC gave us a reference chart for security control layers:

| Layer | Controls |
|---|---|
| Applications | Web app firewalls, software development life cycle (SDLC), binary analysis, application scanners, etc. |
| Information | Database monitoring, encryption, data loss prevention (DLP), content management framework (CMF) |
| Management |  Patch and configuration management, governance and compliance, virtual machine administration, identity and access management (IAM), etc.|
| Network  | Firewalls, network intrusion detection/prevention, quality of service (QoS), DNS security, etc. |
| Trusted Computing | Hardware and software roots of trust (RoT) and APIs, etc. | 
| Computer and storage | Host-based intrusion detection/prevention and firewalls, log management, file integrity efforts, encryption, etc. |
| Physical | Physical security measures, video monitoring, guards, etc. | 

<u>**Cloud Threats**</u>

OWASP is back again, to provide us with a Top 10 regarding Cloud Security Risks (https://faun.pub/owasp-cloud-top-10-db4a3a8e0a8f): 

- **R1: Accountability & Data Risk**: Using public cloud can introduce risk for data recovery.
- **R2: User Identity Federation**: Multiple user identities in multiple providers adds tremendous complexity to user ID management.
- **R3: Legal & Regulatory Compliance**: Different regulatory laws in different countries add complexity to an already challenging arena.
- **R4: Business Continuity & Resilience**: Since using the cloud transfers business continuity efforts to the provider, business or financial loss could occur if there is a problem with the provider.
- **R5: User Privacy & Secondary Usage of Data**: User personal data and privacy can be put at risk.
- **R6: Service & Data Integration**: Eavesdropping and interception can occur if data is not secured in transit.
- **R7: Multi-tenancy & Physical Security**: If tenants within the cloud are not properly segmented, security features may be interfered with or altered (knowingly or unknowingly).
- **R8: Incidence Analysis & Forensics**: Distribution of storage may frustrate law enforcement forensic efforts.
- **R9: Infrastructure Security**: Infrastructure misconfiguration can interject issues and allow unauthorized scanning.
- **R10: Non-production Environment Exposure**: Unauthorized access and data disclosure can increase with the use of non-production environments.

> Another top 10 from OWASP to mention is: Top 10 Serverless Security Risk: https://github.com/OWASP/Serverless-Top-10-Project

We can use some tools depending on the model architecture we have, just to mention some tools:
- Core CloudInspect: Profits from Core Impact & Core Insight technologies to offer penetration testing as a serivce from Amazon Web Services for EC2 users
- CloudPassage Halo: Provides instant visibility and continuous protection for servers in any combination of data centers, private clouds and public clouds. 
- Qualys Cloud Suite
- Trend Micro's Instant-On Cloud Security
- Panda Cloud Officve Protection

> Amazon does allow for independent security testing (https://aws.amazon.com/security/penetration-testing), but the rules are very strict about what you can and you can't do.

CSA released a publication titled "The Dirty Dozen: 12 Top Cloud Security Threats" (https://www.computerworld.com/article/1659770/the-dirty-dozen-12-cloud-security-threats-2.html) this link is not in the books, but I added to give more context. 

> Shadow IT refers to IT systems and solutions that are developed to handle an issue but aren't necessarily taken through proper organizational approval chains. "Just get the job done" works in many situations, but having shadow IT around - even in the cloud - can be a recipe for disaster.

SOA (service-oriented architecture) is a design approach that makes it easier for application components to cooperate and exchange information on systems connected over a network. It is designed to allow software components to deliver information directly to other components over a network.

<u>**Cloud Attacks and Mitigations**</u>

We will mention some interesting cloud-based attacks:

- **Session Riding**: is simply CSRF (cross-site request forgery) under a different name and deals with cloud services instead of traditional data centers.
- **Side Channel Attack**: aka *cross-guest VM breach*, deals with the virtualization itself. If an attacker can somehow gain control of an existing VM (or place his own) on the same physical host as the target, he may be able to pull off lots of attacks.
- **Cloudbourne**: Takes advantage of vulnerabilities in the bare-metal cloud server itself, using backdoor channels to bypass security operations.
- **Man-in-the-cloud (MITC)**: Attacker abusescloud file synchronization services to intercept and manipulate communications. 
- **Cloud Hopper**: Occurs when an attacker uses spear phishing campaign with custom malware to compromise cloud service staff and firms. 
- **Wrapping attack**: Where SOAP message is intercepted and the data in the envelope is changed and then sent/replayed

> When an attacker who has access to physical host would add another VM in an effort to steal data from the target. Since people who administer the hardware and fabric of the system cannot access user data.

---

<u>**Cloud Hacking**</u>

We will mention one resource to gain practice to be familiarized with cloud hacking: 
- CloudGoat (https://rhinosecuritylabs.com/aws/cloudgoat-vulnerable-design-aws-environment/) 

After we have practiced pentesting basis, hacking cloud has the same steps that we always knew: Identify targets, scan them for vulnerabilities, enumerate as much information as you can, stage attacks based on all this knowledge, gain (and maintain) access, and carry out exploits. 

Tools for container vulnerability scanning include:
- Trivy
- Clair
- Dadga
- Sysdig (for Kubernetes cluster vulnerabilities in particular)

Enumeration in cloud services involves a lot different avenues:
- Amazon Simple Storage Service (S3) *buckets* are cloud services that stores files, folders, and other informationfrom various applications.
- We can enumerate AWS Account IDs through everything from error messages, code repositories, and Lambda functions to simply checking boards where folks are posting help requests.
- In terms of IAM, AWS error messages tend to help in enumerating these roles, providing information on services in use, any third-party tie-ins, and IAM user names.

> Kubernetes setups store cluster data, API objects, and service discovery details in a distributed, key-value storage called "etcd", which can be examined to identify endpoints in the environment.

Tools for attacking cloud services:
- Pacu (https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) is an open source AWS exploitation framework that has been called the "Metasploit of the cloud". Some modules to mention are:
  - **confirm_permissions**: Enumerates a list of confirmed permissions for the current account
  - **privesc_scan**: Abuses 20+ different privilege escalation methods to gain further access
  - **cloudtrail_csv_injection**: Injects malicious formulas into CloudTrail CSV exports
  - **disrupt_monitoring**: Targets GuardDuty, CloudTrail, Config, CloudWatch, and VPC to disrupt various monitoring and logging capabilities
  - **backdoor_users_[keys/passwords]**: Establishes backdoor account access by adding credentials to other IAM user accounts
  - **sysman_ec2_rce**: Abuses the AWS Simple Systems Manager to try and gain root (Linux) or SYSTEM (Windows) level remote code execution on various EC2 instances
  - **backdoor_ec2_sec_groups**: Adds backdoor rules to EC2 security groups to give you access to private services

Other tools of note:
- DumpsterDiver -> used to identify potential leaks and credentials in target clouds.
- Cloud Container Attack Tool (CCAT) -> holds various modules to accomplish things like enumerating repositories and creating/installing a backdoor for future use.
- dockerscan -> a docker analysis and hacking tool that lets you do everything from backdooring a container to scanning registries, manipulating settings, and extracting/modifying images themselves.
- AWS pwn -> a tool that does everything from reconnaissance and gaining access to privilege escalation and clearing tracks.


