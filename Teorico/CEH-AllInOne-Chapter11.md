# Chapter 11: Cryptography 101

<u>**Cryptography**</u>: The science or study of protecting information, wether in transit or at rest, to ensure confidentiality and make it only understable to only intended people.

![Cryptography process basic](https://users.ece.cmu.edu/~adrian/630-f04/PGP-intro_files/fig1-2.gif)

<u>**Cryptoanalysis**</u>: The study and methods used to crack encrypted communications. There are three methods to mention:
- **Linear Cryptonalysis** (Linear Fashion) --> (Mitsuru Matsui, 1993) 
  - Works best on block ciphers.
  - Take blocks of known text and compare them to blocks of the encrypted text, line by line, from front to back.
- **Differential Crytoanalysis**
  - Applicable to symmetric key algorithms and basically compares differences in inputs to how each one affects the outcome.
- **Integral Cryptoanalysis**
  - Uses the same input versus output comparison but also runs multiple computations of the same block size input.
<br><br>

> <u>**Plain text**</u>
<br>Refers to any text that it is not encrypted.

## Encryption Algorithms and Techniques

<u>**Encryption Algorithms**</u>
<br>
These are mathematical formulas used to encrypt and decrypt data. It can be refered as **Ciphers**. <br>
In modern-day systems, these algorithms, usually depend on a key, which it is lost, the algorithm would be useless. <br>
There are two main methods by which these keys can be used: **symmetric and asymmetric**.

> Resources to learn mor about cryptography stuff: https://www.cryptool.org/en/

<u>**Methods of encryption algorithms**</u>

- Stream Cipher
  - Its bits are encrypted as a continuous stream (one at a time).
  - Work at a high speed.
  - Usually encrypted by XOR operation
- Block Cipher
  - Data bits are split up into blocks, each block (commonly 64 bits at a time) is encrypted with the key and algorithm.
  - Usually encrypted by methods such as substitution and transposition.
  - It is deemed slower than Stream Ciphers.

> The two methods above, are considered ciphers based on the **input data**. The following are based on the **key used**.

<u>**Symmetric Encryption**</u>
<br>
Also known as *Single key* or *Shared key encryption*. This secret key is only known by the sender and the receiver.
<br> It is ideal when it comes to Bulk Encryption, it is faster. However this encryption has some weaknesses. For example, key distribution and management is difficult, trying to share the secret key with the intended person.

We will list some symmetric algorithms:
<br>
- **DES**
  - Block Cipher
  - 56-bit key (8 bit reserved for parity)
  - Currently, considered no longer secure.
- **3DES**:
  - Block Cipher
  - 168-bit key, can use up to 3 keys in a multiple-encryption method.
  - Better than DES, but slower.
- **AES (Advanced Encryption Standard)**:
  - Block Cipher
  - Key length of 128, 192, or 256 bits
  - Much faster than DES and 3DES
- **IDEA (International Data Encryption Algorithm)**:
  - Block Cipher
  - 128-bit key
  - Used in Pretty Good Privacy (PGP) 2.0
- **Twofish**:
  - Block Cipher
  - Key sized **up to** 256 bits.
- **Blowfish**:
  - Fast Block Cipher
  - Keys from 32 to 448 bits
  - Considered public domain
- **RC (Revest Cipher)**:
  - Encompasses from RC2 to RC6
  - Block Cipher
  - Key length **up to** 2040 bits
  - RC6 (128-bit blocks and 4-bit working registers), RC5 (block size 32, 64 or 128 and 2-bit working registers)
- **Serpent**:
  - Block Cipher
  - Key length of 128, 192 or 256 bits
  - 32 rounds of computational operations
- **TEA (Tiny Encryption Algorithm)**:
  - Use Feistel Cipher (Block Cipher)
  - 64 rounds of operations
  - 128 or 64 bit keys
- **GOST**:
  - aka Magma
  - 32-round Feistel cipher
  - Use 256-bit keys.
- **Camellia**:
  - 18 or 24-round cipher
  - 128-256-bit length
  - Used as part of TLS

Symmetric encryption does great job with confidentiality, but does nothing regarding other security measure.

<u>**Asymmetric Encryption**</u>
<br>Also known as a Public Key Cryptography. It appeared to solve the problem related to the weakness of Symmetric Algorithm, regarding key distribution.
<br>This method use two keys, both are generated together.
- Encryption key = Public key
- Decryption key = Private key

This algorithm also addresses the nonrepudiation problem.

We will list some asymmetric algorithms:

- **Diffie-Hellman**: 
  - For key exchange protocol: TLS, SSL and IPSec
  - It could be vulnerable to MiTM, however, if the use of digital signature is waived
- **Elliptic Curve Cryptosystem (ECC)**:
  - Uses less processing power than others, ideal for mobile devices
- **RSA**:
  - Use of two large prime numbers, factoring these numbers creates a key sizes up to 4096 bits.
  - Can be used for encryption and Digital Signatures
- **El Gamal**:
  - Uses the solving of discrete logarithm problems for encryption and Digital Signatures

> Asymmetric is slower than symmetric, and even it consumes more processing power, because of the needs of longer keys and it is ideal for smaller amount of data.

> DUHK attack "**Don't Use Hard-coded Keys**" (https://duhkattack.com/) refers to a vulnerability that allows attackers access to keys in certain VPN implementations. Affect devices using ANSI X9.31 random number generator (RNG) with hard-coded seed key.

<u>**Hash Algorithms**</u>

A hashing algorithm is a *one-way* mathematical function that takes an input and produces a fixed-length string (usually a number), or hash. Its purpose is to **provide a means to verify the integrity** of a piece of data, if we change a single little bit, we would get a completely different hash.

> Hash is important for providing integrity checks, it is no designed to be an encryption method. Teorically, **hashes can not be reverse-engineered**.

<br>
We will list some hash algorithms:

- **MD5 (Message Digest algorithm)**:
  - Output of 128-bit hash, expressed as 32-digit hexadecimal number
  - It is currently obsolete, but it some particular cases it is still usef for verification downloads and storing passwords.
- **SHA-1**:
  - Output of 160-bit hash
  - Developed by the NSA 
- **SHA-2**:
  - Holds four separate hash functions that produce output of 224, 256, 384 and 512 bits.
  - Designed to replace SHA-1, after the year 2010
- **SHA-3**:
  - Use a method called "sponge construction"
- **RIPEMD-#**:
  - RACE Integrity Primitives Evaluation Message Digest
  - The **#** indicates the bit length, e.g. RIPEMD.160 or RIPEMD-256.
  - Works through 80 stages (5 blocks 16 times each)

**Collision Attack**
<br>Hashing Algorithms are not impervious, the effort to crack these hashes are called *collision* or a *collision attack*. The following image shows an example of a collision.

![Collision example](https://library.mosse-institute.com/_images/collision_attack.jpg)

An attacker can take advantages of it, by sending a malicious file to the victim make them to believe they are receiving the legitimate file by checking the hash matched.

> Regarding MD5, you can see more examples here: https://www.mscs.dal.ca/~selinger/md5collision/

In the case of storing passwords, attacker can get your hash and start and brute force attack, and comparing hash against hash, no nedeed to know the plain password, since hash is teorically not reversible.

**Rainbow Tables**: Kind a database of texts converted in hash, in order to find a specific hash and link it to a plain text pre-processed.

> In modern systems this kind of attack may be useless: https://blog.ircmaxwell.com/2011/08/rainbow-table-is-dead.html

To solve these issues, of Collision of Rainbow Tables, a new concept emerged, called *salt*, which is a collection of random bits that is used a key to the hashing algorithm. 

![Example of Salt](https://aspblogs.blob.core.windows.net/media/jcogley/WindowsLiveWriter/SymmetricSalting_A21/withsalting_2.png)

**Tools to create and view hashes**
- https://download.cnet.com/developer/slavasoft/i-89898/
- https://www.bullzip.com/products/md5/info.php
- https://www.nirsoft.net/
- For mobile devices: *Hash Droid*
---
<u>**Steganography**</u>

It is the practice of concealing a message inside another medium (such as another file or an image) in such a way that only the sender and the recipient even know of its existence, let alone the manner in which to decipher it.

![Example of Steganography](https://www.sentinelone.com/wp-content/uploads/2019/07/3-anon-.jpg)

There are 3 main techniques:
- Least significant bit insertion
- Masking and filtering (e.g. grayscale images)
- Algorithmic transformation

> Detecting a stego-file could be challeging, but a common indicator is its file size, it is usual that the stego-file to be longer than the original file, regarding images; and maybe finding some weird color palette "faults". Audio and video require some statistical analysis with other tools.

Somes tools:
- OmniHide Pro
- Masker
- DeepSound or MP3Stego (for audios)
- Quickstego
- Gifshuffle
- SNOW
- Steganography Studio
- OpenStego
---
<u>**Hardware Encryption**</u>

The use of computer software (such a dedicated processor) to assist software in encryption data. Due to it is a dedicated, it does not have to, freeing it up to do the tasks; offers faster algorithm processing, tamper-proof/resistant key storage and protection against malicious code.

There are several hardware encryption devices, but for CEH, we will focus on four of them:
- **USB Encryption**
- **Hard Drive Encryption**
- **HSM (Hardware Security Module)**: external security device used to manage, generate, and store cryptography keys
- **TPM (Trusted Platform Module)**: chip or processor present on system motherboards that performs cryptographic functions and stores encryption keys.

---
> **Homomorphic Encryption**
<br> It is when you need to work on an encrypted data, but you cannot decrypt it. The main idea is that a system exists where quasi-encryption could be "around" the data where certain operations could take place on the ciphertext.

---

## PKI, the Digital Certificate, and Digital Signature

**The PKI System**
<br> It is a system designed to verify and authenticate the identity of a user within an enterprise taking part in a data exchange.

Certificate Authority (CA) may be internal and there could be any number of subordinate CAs - *registration authorities (RAs)* to handle internal things. Most root CAs are removed from network to protect integrity of the system.
<br>CA acts as a third party to the organization, similiar to a notary; things are signed by this CA, it means you can trust on that thing. CA creates and issue digital certificates, and keeps track of all certificates using certificate management system and *certificate revocation list (CRL)* for all those which were revoked.

![PKI Example](https://i.ytimg.com/vi/5OqgYSXWYQM/maxresdefault.jpg)

    Trust model
    ------------
    Describes how entites within an enterprise deals with keys, signatures and certificates.
    There are three basic models:
    - Web of trust
    - Single-authority system
    - Hierarchical trust system (most secure)

> A CA can be set up to trust another CA from different PKI, this is called *cross-certification*, allows them to validate certificates generated from either side.

<br>

**Digital Certificates**

It is an electronic file that is used to verify a user's identity, providing nonrepudiation throughout the system. It follows the X.509 standard. Any system complying with X.509 can exchange and use digital certificates to establish authenticity.

Content of a digital certificate:
- **Version**: Identifies certificate format, the common version is 1
- **Serial Number**: Serial number to identify the certificate
- **Subject**: Whoever or whatever is being identified by the certificate
- **Algorithm ID (or Signature Algorithm)**: Algorithm used to create the digital signature
- **Issuer**: Entity that verifies the authenticity of the certificate, the one who creates the certificate
- **Valid From and Valid To**: Show the range of dates
- **Key Usage**: Purpose for it was created
- **Subject's Public Key**: A copy of the subject's public key is included in the digital certificate
- **Optional**: Include Issuer Unique Identifier, Subject Alternative Name, and Extensions

When someone applies to get a certificate, CA will sign the certificate of the applicant before he sent it using the CA's *private key*. And the only key to decrypt it, it is the CA's public key, which is readily to anyone in the PKI infrastructure. 

- **Signed Certificates**: It is created internally only for those purposes, e.g. authentication via certificates for internal applications or services. It is common to find it even in enterprise-level netowrks. It is easy to put in place, due to user generate and signs (using his own private key) his own certificate.
- **Self-signed Certificates**: Indicate the CA is involved and the signature validating the identity of the entity is confirmed via an external source. For external connectivity requires this kond of certificate.

> Case of compromising root companies (root CA that companies usually trust): https://www.csoonline.com/article/548734/hacking-the-real-security-issue-behind-the-comodo-hack.html

<br>

**Digital Signatures**

It is nothing more than an algorithmic output that is designed to ensure the authenticity (and integrity) of the sender - basically a hash algorithm. It works according to the following steps:

1. User1 creates a text messages and send to User2
2. User1 runs his message through a hash and generates an outcome
3. User1 encrypts the outcome with his *private key* and sends it to User2
4. User2 recieves it and attempts to decrypt the hash with User1's *public key*. **If it works, he knows the message came from User1 because the only thing User1's public key could ever decrypt is something that was encrypted using his private key in first place.**
<br>
<br>
> FIPS 186-4 specifies Digital Signature Algorithm (DSA) is used in the generation and verification of digital signatures.

<hr>

## Encrypted Communication and Cryptographic Attacks

Data at rest (DAR), means data that is in stored state and not currently accesible. <br> DAR vendors are tasked with the objective to protect data on mobile devices and laptops from loss or theft in resting state. This entails *full disk encryption (FDE)*, where pre-boot authentication is necessary to "unlock" the drive before the system can even boot up. 

FDE can be software or hardware based, and it can use network-based authentication (e.g. AD) and/or local authentication sources (local account or locally cached from a network source). For software-based, Microsoft provided **BitLocker** on Pro and other versions, McAfee with Endpoint Encryption, and Symantec Drive Encryption and Gilisoft Full Disk Encryption.

It is worth to mention, to not confuse FDE with a pre-boot authentication system (which change the MBR) and individual volume, folder, and file encryption. Tools for example, Microsoft builds Encrypting File System (EFS) into it operating systems for files, folders and drives needing encryption. Other tools: VeraCrypt, AxCrypt, and GNU Privacy Guard (GnuPG).

### 1. Encrypted Communication

We talked about DAR, but now we will focus in Data in Transit, how to transport securely.

There are several ways to communicate securely with another one, but the exam, we list the following:
- **Secure Shell (SSH)**: 
  - Secure version of Telnet
  - TCP port 22 by default
  - Use of public key cryptography
  - SSH2 is the sucessor to SSH, more secure, efficient and portable, includes a built-in encrypted version of FTP (SFTP)
- **Secure Socket Layer (SSL)**: 
  - Encrypts data at the Transport Layer (OSI Model) and above, for secure communication accross internet.
  - Use of RSA encryption and Digital Certificates
  - It was replaced by TLS
- **Transport Layer Security (TLS)**: 
  - Using RSA of 1024 and 2048 bits
  - Sucessor of SSL
  - The handshake portion allows client and server authenticates each other
  - TLS Record Protocol, provides secured communication channel
- **Internet Protocol Security (IPSec)**: 
  - Network Layer tunneling protocol that can be used in two modes:
    - Tunnel -> entire IP packet encrypted
    - Transport -> data payload encrypted
  - Authentication Header (AH) protocol verify IP's integrity and authentication validation, but not confidentiality
  - Encapsulating Security Payload (ESP) encrypts each packet, in Transport mode only data is encrypted not the headers; meanwhile in tunnel packet and header are encrypted.
- **Pretty Good Privacy (PGP)**: 
  - Used for signing, compression, and encrypting and decrypting e-mails, files, directories, and even the whole disk partition, mainly in a effort to increase the security of e-mail communications.
  - Follows OpenPGP standard
  - It is known as hybrid, because it uses features of conventional and public key cryptography.

> S/MIME (Secure/Multipurpose Internet Mail Extentions), developed by RSA Data Security, and it is a standard for public key encryption and signing of MIME data. The main difference between PGP and S/MIME is that PGP can be used to encrypt not only e-mail messages, but also files and entire drives.

Despite these methods are "secure" methodsof communications, there is always a probability that these could be vulnerated. For example, in 2014, was a bad year for SSL due to the emergence of Heartbleed and POODLE, apparently came out of nowhere. 

    Heartbleed
    ----------
    -Exploits a small feature in OpenSSL
    -OpenSSL uses a heartbeat during an open session to verify that data was received correctly, does this by "echoing" data back to the other system.
    -An attacker sends a single byte of data while telling the server it sent 64Kb of data, the server will send back 64Kb of random data from its memory
    -In memory, there could be names, passwords, private keys, cookies, and a host. 

The following command is used to search for Heartbleed vulnerability: the expected response would be **State: NOT VULNERABLE**
```bash
nmap -d --script ssl-heartbleed --script-args vulns.showall -sV [host]
```
In metasploit the module related is **openssl_heartbleed**.
It is also woth to mention **reverse Heartbleed** (where servers are able to perfom the same thing in reverse, stealing data from clients).

> FREAK (Factoring Attack on RSA-EXPORT Keys) is a man-in-the-middle attack that forces a downgrade of RSA key to a weaker length. The attacker forces the use of a weaker encryption key length, enabling succesful brute-force attacks.

    POODLE (Padding Oracle On Downgraded Legacy)
    --------------------------------------------
    -A matter of backward compatibility
    -TLS clients perform handshake, designed to degrade service until something acceotable was found.
    -A hacker could intercept the communication in the handshake, making them fall, which results in the dropping to SSL 3.0 (use RC4)
    -SSL 3.0 allows padding data at the end of a block cipher to be changed, which is less secure, usually called "RC4 biases" (https://openssl-library.org/files/ssl-poodle.pdf)
    -Mitigation this, it is basically not using SSL 3.0 at all; completely disabling it on the client and server side means the "degradation dance" can't ever take things down to SSL 3.0
    -Another way to mitigate is by implementing TLS_FALLBACK_SCSV to prevent POODLE (browsers like Google and Firefox use it)
    -Or finally using "anti-POODLE" record splitting

Additionally, another attack worth to mention is **DROWN** (Decrypting RSA with Obsolete and Weakened eNcryption), per the website (https://drownattack.com/), this vulnerability affects services thar rely on SSL/TLS like HTTPS for example, attackers can break the encryption and gather everything (including sensitive information). The mitigation is similar to POODLE: turn off support for SSLv2, and server operations need to ensure that their private keys are not used anywhere that supports SSLv2 connections.

> Antoher note to be taken into account is:
> <br> - CVE-2014-0160 ---> Heartbleed
> <br> - CVE-2014-3566 ---> POODLE (aka PoodleBleed)

### 2. Cryptography Attacks

We will list some methods or tools to crack encryption:

- **Known plain-text attack**: The use of plain and their cipher texts, the more, the better. By comparing these, over the time, we can get the key.
- **Chosen plain-text attack**: The attacker encrypts multiple plain-text copies himself in order to gain the key.
- **Adaptive chosen plain-text attack**: The attacker sends bunches of cipher texts to be encrypted and then uses the results of the decryptions to select different, closely related cipher texts.
- **Cipher-text-only attack**: Hacker gains copies of several messages encrypted with the same algorithm, and then use statistical analysis to reveal, eventually, repeating code, which is used to decode the message.
- **Replay attack**: The most often used in Man-in-the-Middle Attack. This is based on the repetition (in the time right) of a portion of a cryptographic exchange to fool the system and set up a channel. Session tokens is used to combat this attack.
- **Chosen cipher attack**: chosen a particular cipher-text message and tries to get the key through comparative analysis with multiple keys and a plain-text version. RSA is particularly vulnerable to this attack.
----
- **Side-chanel attack**: It is not like the other ones, it is a physical attack that monitors environmental factors (like power consumption, timing, and delay) on the cryptosystem itself.

Some tools for cracking:
- Carnivore and Magic Lantern (created by US government to FBI)
- L0phtcrack (https://l0phtcrack.gitlab.io/)
- John the Ripper
- PGPCrack
- CrypTool (https://www.cryptool.org/en/)
- CryptoBench (https://cryptobench.org/)

