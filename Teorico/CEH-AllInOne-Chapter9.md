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





