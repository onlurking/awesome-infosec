Awesome Infosec
===============

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome information security resources, inspired by the awesome-* trend on GitHub and my previous [Coderwall](https://coderwall.com/p/sr1olq/information-security-open-courses-documentation) publication.

The goal is to build a categorized community-driven collection of free resources focused on information security skill sets like:

* Penetration Testing, Vulnerability Assessment
* Computer Forensics, Malware Analysis, Reverse Engineering
* Hardening, Honeypot Deployment, Network Security
* Cryptography and Anonimity

Those resources and tools are intended only for cybersecurity professional and educational use in a controlled environment.

Table of Contents
=================

1. [Massive Online Open Courses](#massive-online-open-courses)
2. [Academic Courses](#academic-courses)
3. [Laboratories](#laboratories)
4. [Capture the Flag](#capture-the-flag)
5. [Open Security Books](#open-security-books)
6. [Related Awesome Lists](#related-awesome-lists)
7. [Contributing](#contributing)
8. [License](#license)


Massive Online Open Courses
===========================

#### Stanford University - Computer Security
In this class you will learn how to design secure systems and write secure code. You will learn how to find vulnerabilities in code and how to design software systems that limit the impact of security vulnerabilities. We will focus on principles for building secure systems and give many real world examples. 

  * [Stanford University - Computer Security](https://www.coursera.org/course/security)

#### Stanford University - Cryptography I
This course explains the inner workings of cryptographic primitives and how to correctly use them. Students will learn how to reason about the security of cryptographic constructions and how to apply this knowledge to real-world applications. The course begins with a detailed discussion of how two parties who have a shared secret key can communicate securely when a powerful adversary eavesdrops and tampers with traffic. We will examine many deployed protocols and analyze mistakes in existing systems. The second half of the course discusses public-key techniques that let two or more parties generate a shared secret key. We will cover the relevant number theory and discuss public-key encryption and basic key-exchange. Throughout the course students will be exposed to many exciting open problems in the field.

  * [Stanford University - Cryptography I](https://www.coursera.org/course/crypto)

#### Stanford University - Cryptography II
This course is a continuation of Crypto I and explains the inner workings of public-key systems and cryptographic protocols.   Students will learn how to reason about the security of cryptographic constructions and how to apply this knowledge to real-world applications. The course begins with constructions for digital signatures and their applications.   We will then discuss protocols for user authentication and zero-knowledge protocols.    Next we will turn to privacy applications of cryptography supporting anonymous credentials and private database lookup.  We will conclude with more advanced topics including multi-party computation and elliptic curve cryptography.

  * [Stanford University - Cryptography II](https://www.coursera.org/course/crypto2)

#### University of Maryland - Usable Security
This course focuses on how to design and build secure systems with a human-centric focus. We will look at basic principles of human-computer interaction, and apply these insights to the design of secure systems with the goal of developing security measures that respect human performance and their goals within a system.

  * [University of Maryland - Usable Security](https://www.coursera.org/course/usablesec)

#### University of Maryland - Software Security
This course we will explore the foundations of software security. We will consider important software vulnerabilities and attacks that exploit them -- such as buffer overflows, SQL injection, and session hijacking -- and we will consider defenses that prevent or mitigate these attacks, including advanced testing and program analysis techniques. Importantly, we take a "build security in" mentality, considering techniques at each phase of the development cycle that can be used to strengthen the security of software systems.

  * [University of Maryland - Software Security](https://www.coursera.org/course/softwaresec)

#### University of Maryland - Cryptography
This course will introduce you to the foundations of modern cryptography, with an eye toward practical applications. We will learn the importance of carefully defining security; of relying on a set of well-studied â€œhardness assumptionsâ€ (e.g., the hardness of factoring large numbers); and of the possibility of proving security of complicated constructions based on low-level primitives. We will not only cover these ideas in theory, but will also explore their real-world impact. You will learn about cryptographic primitives in wide use today, and see how these can be combined to develop modern protocols for secure communication.

  * [University of Maryland - Cryptography](https://www.coursera.org/course/cryptography)

#### University of Maryland - Hardware Security
In this course, we will study security and trust from the hardware perspective. We will start with a short survey of the roles of hardware in security and trust. With all types of dedicated hardware/circuits, known as co-processors, being developed to speed up application specific computations, hardwareâ€™s role changes from the enabler to an enhancer. Nowadays, hardware becomes the enforcer for secure systems because it is used to ensure that only the authenticated user and software can access the processor. However, current hardware design flow does not have security as a key design objective. Consequently, we will conduct several case studies where hardware turns into the weakest link in secure systems.

  * [University of Maryland - Hardware Security](https://www.coursera.org/course/hardwaresec)

#### Cybrary - Online Cyber Security Training
Cyber Security jobs are growing three times faster than information technology jobs. However, this rapidly growing and very exciting industry lacks the number of skilled professionals required to handle the jobs. Some common  jobs within Cyber Security include information assurance, security analyst, penetration tester, malware analyst/reverse engineering and Intel. With these types of opportunities available, aspiring or growing Cyber Security professionals should focus on continually increasing their skill set, because the Cyber Security industry never rests, it is continually changing. However, traditionally, Cyber Security classes are the most expensive training classes. As you know, that barrier to entry has been removed.

  * [CompTIA    Security+](http://www.cybrary.it/course/comptia-security-plus/) <br>
  In this class you will gain a stable foundation of Cyber Security and Information Assurance as well as prepare for the security industryâ€™s most sought after entry level certification.

  * [Cryptography](http://www.cybrary.it/course/cryptography/) <br>
  Learn how to secure data communications through the use of cryptographic messaging and practices.

  * [Ethical Hacking and Penetration Testing](http://www.cybrary.it/course/ethical-hacking/) <br>
  Learn the fundamentals of hacking and penetration testing. Think like a hacker, so that you can stop them from intruding into your systems. This class will help prepare you for the industries most sought after certification, EC-Councilâ€™s CEH.

  * [Computer and Hacking Forensics](http://www.cybrary.it/course/computer-hacking-forensics-analyst/) <br>
  In order to catch cyber criminals, you have to learn how to retrace their steps and correctly acquire and document the evidence. Also prepare for the industry leading CHFI certification from the EC-Council.

  * [CompTIA Advanced Security Practitioner (CASP)](http://www.cybrary.it/course/comptia-casp/) <br>
  This advanced certification covers deep topics that span across both Cyber Security as well as Information Assurance.

  * [ISACA Certified Information Systems Auditor (CISA)](http://www.cybrary.it/course/cisa/) <br>
  Become an expert in information systems auditing and controlling with this leading auditor certification from ISACA.

  * [Certified Information Systems Security Professional (CISSP)](http://www.cybrary.it/course/cissp/) <br>
  The leading certification for Information Assurance management personnel. This course is both very deep, and very broad. Be ready to study hard!

  * [Post Exploitation](http://www.cybrary.it/course/post-exploitation-hacking/) <br>
  Learn what to do to maintain your presence and to gather intelligence after you have exploited the target system.

  * [Social Engineering and Manipulation](http://www.cybrary.it/course/social-engineering/) <br>
  Take a look inside the form, function and flow of a highly skilled social engineering cyber-attack. Learn to protect the human element.

  * [Python for Security Professionals](http://www.cybrary.it/course/python-security-professionals/) <br>
  Learn the commands and functions that every aspiring cyber security professional must know from Python. This isnâ€™t a full programming course, but rather a course designed for non-coders who are developing their career in security.

  * [Metasploit](http://www.cybrary.it/course/metasploit/) <br>
  An in-depth look inside the Metasploit Framework intended to show you how to use it to its full potential.

  * [Malware Analysis and Reverse Engineering](http://www.cybrary.it/course/malware-analysis/) <br>
  An introduction to reverse engineering malware. This class is for experienced Cyber Security professionals, generally at least two to three years in the field is preferred.

  * [Advanced Penetration Testing by Georgia Weidman](http://www.cybrary.it/course/advanced-penetration-testing/) <br>
  This class is for advanced Cyber Security professionals. You will learn in depth, hands-on, advanced hacking techniques to help you target and penetrate almost any highly secured environment.

#### SANS Cyber Aces
SANS Cyber Aces Online makes available, free and online, selected courses from the professional development curriculum offered by The SANS Institute, the global leader in cyber security training. SANS goal in making these courses available as open courseware is to help grow the talent pool and accelerate the rate at which skilled cyber professionals can enter the information security industry â€“ filling mission critical jobs currently going unfilled.

  * [SANS Cyber Aces Online Courses](http://www.cyberaces.org/courses/)
  * [SANS Cyber Aces Online Tutorials](https://tutorials.cyberaces.org/tutorials)

#### Open Security Training

  * [Android Forensics & Security Testing](http://opensecuritytraining.info/AndroidForensics.html) <br>
This course will cover the most common issues facing mobile devices, and general tips for securing mobile applications. Upon completion of general mobile security overview, the course will delve into a proven practice in Mobile Device Forensics and Mobile Application Penetration Testing for Android devices. Over the two-day course, students will get hands-on time with open-source and commercial forensics tools, setup and explore reverse engineering development environments, and experience the process with which professional mobile security engineers have successfully applied to several projects. Areas covered include, identifying application vulnerabilities, code analysis, memory & file system analysis, and insecure storage of sensitive data.

  * [Certified Information Systems Security Professional (CISSP)Â® Common Body of Knowledge (CBK)Â® Review](http://opensecuritytraining.info/CISSP-Main.html) <br>
The CISSP CBK Review course is uniquely designed for federal agency information assurance (IA) professionals in meeting NSTISSI-4011, National Training Standard for Information Systems Security Professionals, as required by DoD 8570.01-M, Information Assurance Workforce Improvement Program.

  * [Flow Analysis & Network Hunting](http://opensecuritytraining.info/Flow.html) <br>
This course focuses on network analysis and hunting of malicious activity from a security operations center perspective. We will dive into the netflow strengths, operational limitations of netflow, recommended sensor placement, netflow tools, visualization of network data, analytic trade craft for network situational awareness and networking hunting scenarios.

  * [Hacking Techniques and Intrusion Detection](http://opensecuritytraining.info/HTID.html) <br>
This course covers the most common methods used in computer and network hacking with the intention of learning how to better protect systems from such intrusions. These methods include reconnaissance techniques, system scanning, accessing systems by network and application level attacks, and denial of service attacks. During the course students will complete many hands on exercises.

  * [Introductory Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86.html) <br>
Intel processors have been a major force in personal computing for more than 30 years. An understanding of low level computing mechanisms used in Intel chips as taught in this course serves as a foundation upon which to better understand other hardware, as well as many technical specialties such as reverse engineering, compiler design, operating system design, code optimization, and vulnerability exploitation.

  * [Introductory Intel x86-64: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86-64.html) <br>
Intel processors have been a major force in personal computing for more than 30 years. An understanding of low level computing mechanisms used in Intel chips as taught in this course serves as a foundation upon which to better understand other hardware, as well as many technical specialties such as reverse engineering, compiler design, operating system design, code optimization, and vulnerability exploitation.

  * [Introduction to ARM](http://opensecuritytraining.info/IntroARM.html) <br>
ARM processors are becoming ubiquitous in mobile devices today with RISC processors making a comeback for their applications in low power computing environments. With major operating systems choosing to run on these processors including the latest Windows RT, iOS and Android, understanding the low level operations of these processors can serve to better understand, optimize and debug software stacks running on them. This class builds on the Intro to x86 class and tries to provide parallels and differences between the two processor architectures wherever possible while focusing on the ARM instruction set, some of the ARM processor features, and how software works and runs on the ARM processor. 

  * [Introduction to Cellular Security](http://opensecuritytraining.info/IntroCellSec.html) <br>
This course is intended to demonstrate the core concepts of cellular network security. Although the course discusses GSM, UMTS, and LTE - it is heavily focused on LTE. The course first introduces important cellular concepts and then follows the evolution of GSM to LTE. 

  * [Introduction to Network Forensics](http://opensecuritytraining.info/NetworkForensics.html) <br>
This is a mainly lecture based class giving an introduction to common network monitoring and forensic techniques.  This class is meant to be accompanied by lab exercises to demonstrate certain tools and technologies, but the lab exercises are not absolutely necessary to convey the operating concepts.

  * [Introduction to Secure Coding](http://opensecuritytraining.info/IntroSecureCoding.html) <br>
The purpose of this course is to provide developers with a short, focused primer related to secure coding.  The hope is that each developer will leave the course with a better understanding of how they can improve, from a security perspective, the code that they write.  This course provides a look at some of the most prevalent security related coding mistakes made in industry today.  Each type of issue is explained in depth including how a malicious user may attack the code, and strategies for avoiding the issues are then reviewed.  Knowledge of at least one programming language is required, although the specific programming language is not important as the concepts that will be discussed are language independent.  The course will cover many of the weaknesses within the context of a web application, but most of the concepts will apply to all application development.

  * [Introduction to Vulnerability Assessment](http://opensecuritytraining.info/IntroductionToVulnerabilityAssessment.html) <br>
This is a lecture and lab based class giving an introduction to vulnerability assessment of some common common computing technologies.  Instructor-led lab exercises are used to demonstrate specific tools and technologies.

  * [Introduction to Trusted Computing](http://opensecuritytraining.info/IntroToTrustedComputing.html) <br>
This course is an introduction to the fundamental technologies behind Trusted Computing. You will learn what Trusted Platform Modules (TPMs) are and what capabilities they can provide both at an in-depth technical level and in an enterprise context. You will also learn about how other technologies such as the Dynamic Root of Trust for Measurement (DRTM) and virtualization can both take advantage of TPMs and be used to enhance the TPM's capabilities. We will cover major use cases for trusted computing, including machine authentication, data protection, and attestation. This course will also introduce you to the various software resources that exist today to support TPMs, give a high-level overview of related research and development projects, and briefly discuss other trusted computing standards such as Trusted Network Connect which may be relevant to enterprise deployment of TPMs and trusted computing.

  * [Offensive, Defensive, and Forensic Techniques for Determining Web User Identity](http://opensecuritytraining.info/WebIdentity.html)
This course looks at web users from a few different perspectives.  First, we look at identifying techniques to determine web user identities from a server perspective.  Second, we will look at obfuscating techniques from a user whom seeks to be anonymous.  Finally, we look at forensic techniques, which, when given a hard drive or similar media, we identify users who accessed that server.

  * [Pcap Analysis & Network Hunting](http://opensecuritytraining.info/Pcap.html) <br>
Introduction to Packet Capture (PCAP) explains the fundamentals of how, where, and why to capture network traffic and what to do with it.  This class covers open-source tools like tcpdump, Wireshark, and ChopShop in several lab exercises that reinforce the material.  Some of the topics include capturing packets with tcpdump, mining DNS resolutions using only command-line tools, and busting obfuscated protocols.  This class will prepare students to tackle common problems and help them begin developing the skills to handle more advanced networking challenges.

  *  [Malware Dynamic Analysis](http://opensecuritytraining.info/MalwareDynamicAnalysis.html) <br>
This introductory malware dynamic analysis class is dedicated to people who are starting to work on malware analysis or who want to know what kinds of artifacts left by malware can be detected via various tools. The class will be a hands-on class where students can use various tools to look for how malware is: Persisting, Communicating, and Hiding. We will achieve the items above by first learning the individual techniques sandboxes utilize. We will show how to capture and record registry, file, network, mutex, API, installation, hooking and other activity undertaken by the malware. We will create fake network responses to deceive malware so that it shows more behavior. We will also talk about how using MITRE's Malware Attribute Enumeration & Characterization (MAEC - pronounced "Mike") standard can help normalize the data obtained manually or from sandboxes, and improve junior malware analysts' reports. The class will additionally discuss how to take malware attributes and turn them into useful detection signatures such as Snort network IDS rules, or YARA signatures.

  * [Secure Code Review](http://opensecuritytraining.info/SecureCodeReview.html) <br>
This course is designed to help developers bring a secure coding mindset into typical project peer reviews. The course briefly talks about the development lifecycle and the importance of peer reviews in delivering a quality product. How to perform this review is discussed and how to keep secure coding a priority during the review is stressed. A variety of hands-on exercises will address common coding mistakes, what to focus on during a review, and how to manage limited time. Throughout the course, the class will break out into pairs and perform example peer reviews on sample code. Perl will be used for the hands-on exercises; however every attempt will be made to generalize the code such that anyone with an understanding of a coding language will be comfortable.

  * [Smart Cards](http://opensecuritytraining.info/SmartCards.html) <br>
This course shows how smart cards are different compared to other type of cards. It is explained how smart cards can be used to realize confidentiality and integrity of information. Insight is given into the structure and operation of a smart card, the functionality of a smart card operating system and commonly used security mechanisms. In addition, an overview is given of developments in the field of chips (8, 16 and 32 bit architectures, co-processors), operating systems, virtual machines (Java Card, MULTOS), compatibility (PC / SC, Open Card, EMV) security evaluation (ITSEC, Common Criteria) and physical and logical attack methods (probing, SEM, FIB, DFA, DPA). Biometric identification and authentication using smart cards is dealt along with a summary of developments and (im) possibilities.

  * [The Life of Binaries](http://opensecuritytraining.info/LifeOfBinaries.html) <br>
Along the way we discuss the relevance of security at different stages of a binaryâ€™s life, from the tricks that can be played by a malicious compiler, to how viruses really work, to the way which malware â€œpackersâ€ duplicate OS process execution functionality, to the benefit of a security-enhanced OS loader which implements address space layout randomization (ASLR).

  * [Understanding Cryptology: Core Concepts](http://opensecuritytraining.info/CryptoCore.html) <br>
This is an introduction to cryptology with a focus on applied cryptology. It was designed to be accessible to a wide audience, and therefore does not include a rigorous mathematical foundation (this will be covered in later classes).

  * [Understanding Cryptology: Cryptanalysis](http://opensecuritytraining.info/Cryptanalysis.html) <br>
A class for those who want to stop learning about building cryptographic systems and want to attack them. This course is a mixture of lecture designed to introduce students to a variety of code-breaking techniques and python labs to solidify those concepts. Unlike its sister class, Core Concepts, math is necessary for this topic. Don't have a math degree? A basic understanding of algebra is sufficient - the mathematical principles that are necessary for understanding are included in the lecture. Knowledge of programming is also necessary, and knowledge of python is very helpful.

  * [Introduction to Software Exploits (Exploits 1)](http://opensecuritytraining.info/Exploits1.html) <br>
Software vulnerabilities are flaws in program logic that can be leveraged by an attacker to execute arbitrary code on a target system. This class will cover both the identification of software vulnerabilities and the techniques attackers use to exploit them. In addition, current techniques that attempt to remediate the threat of software vulnerability exploitation will be discussed. 

  * [Exploits 2: Exploitation in the Windows Environment](http://opensecuritytraining.info/Exploits2.html) <br>
This course covers the exploitation of stack corruption vulnerabilities in the Windows environment. Stack overflows are programming flaws that often times allow an attacker to execute arbitrary code in the context of a vulnerable program. There are many nuances involved with exploiting these vulnerabilities in Windows. Window's exploit mitigations such as DEP, ASLR, SafeSEH, and SEHOP, makes leveraging these programming bugs more difficult, but not impossible. The course highlights the features and weaknesses of many the exploit mitigation techniques deployed in Windows operating systems. Also covered are labs that describe the process of finding bugs in Windows applications with mutation based fuzzing, and then developing exploits that target those bugs.

  * [Intermediate Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntermediateX86.html) <br>
Building upon the Introductory Intel x86 class, this class goes into more depth on topics already learned, and introduces more advanced topics that dive deeper into how Intel-based systems work. Example applications include showing how hardware and memory mechanisms are used for software exploits, anti-debug techniques, rootkit hiding, and direct hardware access for keystroke logging.

  * [Advanced x86: Virtualization with Intel VT-x](http://opensecuritytraining.info/AdvancedX86-VTX.html) <br>
The purpose of this course is to provide a hands on introduction to Intel hardware support for virtualization. The first part will motivate the challenges of virtualization in the absence of dedicated hardware. This is followed by a deep dive on the Intel virtualization "API" and labs to begin implementing a blue pill / hyperjacking attack made famous by researchers like Joanna Rutkowska and Dino Dai Zovi et al. Finally a discussion of virtualization detection techniques. 

  * [Introduction to Reverse Engineering Software](http://opensecuritytraining.info/IntroductionToReverseEngineering.html) <br>
Throughout the history of invention curious minds have sought to understand the inner workings of their gadgets. Whether investigating a broken watch, or improving an engine, these people have broken down their goods into their elemental parts to understand how they work. This is Reverse Engineering (RE), and it is done every day from recreating outdated and incompatible software, understanding malicious code, or exploiting weaknesses in software.

  * [Reverse Engineering Malware](http://opensecuritytraining.info/ReverseEngineeringMalware.html) <br>
This class picks up where the Introduction to Reverse Engineering Software course left off, exploring how static reverse engineering techniques can be used to understand what a piece of malware does and how it can be removed.

  * [Rootkits: What they are, and how to find them](http://opensecuritytraining.info/Rootkits.html) <br>
Rootkits are a class of malware which are dedicated to hiding the attackerâ€™s presence on a compromised system. This class will focus on understanding how rootkits work, and what tools can be used to help find them. This will be a very hands-on class where we talk about specific techniques which rootkits use, and then do labs where we show how a proof of concept rootkit is able to hide things from a defender. 

  * [The Adventures of a Keystroke: An in-depth look into keylogging on Windows](http://opensecuritytraining.info/Keylogging.html) <br>
Windows is designed to be compatible with a lot of devices which is why there are a lot of layers in the keystroke handling. The more layers a system has, the more probable it could be compromised by bad guys. There are more than 30 methods for capturing keystrokes from a Windows PC. Methods vary from simple user mode techniques to advanced ones such as IRP hooking. Class currently covers most of the user mode and kernel mode techniques including the undocumented ones which are not described anywhere else but there are still techniques which are not covered in the class such as Raw Input Devices. As for the hardware, we only cover PS/2 keyboards for the moment but documenting USB keyboards is one of the planned topics for near future. 

Academic Courses
================

#### Florida State University's - Offensive Computer Security
The primary incentive for an attacker to exploit a vulnerability, or series of vulnerabilities is to achieve a return on an investment (his/her time usually). This return need not be strictly monetaryâ€”an attacker may be interested in obtaining access to data, identities, or some other commodity that is valuable to them.  The field of penetration testing involves authorized auditing and exploitation of systems to assess actual system security in order to protect against attackers.  This requires thorough knowledge of vulnerabilities and how to exploit them.  Thus, this course provides an introductory but comprehensive coverage of the fundamental methodologies, skills, legal issues, and tools used in white hat penetration testing and secure system administration.

 * [Offensive Computer Security - Spring 2014](http://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity)
 * [Offensive Computer Security - Spring 2013](http://www.cs.fsu.edu/~redwood/OffensiveSecurity)

#### Florida State University's - Offensive Network Security
This class allows students to look deep into know protocols (i.e. IP, TCP, UDP) to see how an attacker can utilize these protocols to their advantage and how to spot issues in a network via captured network traffic.
The first half of this course focuses on know protocols while the second half of the class focuses on reverse engineering unknown protocols. This class will utilize captured traffic to allow students to reverse the protocol by using known techniques such as incorporating bioinformatics introduced by Marshall Beddoe. This class will also cover fuzzing protocols to see if the server or client have vulnerabilities. Overall, a student finishing this class will have a better understanding of the network layers, protocols, and network communication and their interaction in computer networks.

 * [Offensive Network Security](http://www.cs.fsu.edu/~lawrence/OffNetSec/)


#### NYU Polytechnic School of Engineering - ISIS Lab's Hack Night
Developed from the materials of NYU Poly's old Penetration Testing and Vulnerability Analysis course, Hack Night is a sobering introduction to offensive security. A lot of complex technical content is covered very quickly as students are introduced to a wide variety of complex and immersive topics over thirteen weeks.
   * [ISIS Lab's Hack Night](https://github.com/isislab/Hack-Night/)

####  Rensselaer Polytechnic Institute - Modern Binary Exploitation
This course will start off by covering basic x86 reverse engineering, vulnerability analysis, and classical forms of Linux-based userland binary exploitation. It will then transition into protections found on modern systems (Canaries, DEP, ASLR, RELRO, Fortify Source, etc) and the techniques used to defeat them. Time permitting, the course will also cover other subjects in exploitation including kernel-land and Windows based exploitation.

* [CSCI 4968 - Spring '15 Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)

####  Rensselaer Polytechnic Institute - Hardware Reverse Engineering
Reverse engineering techniques for semiconductor devices and their applications to competitive analysis, IP litigation, security testing, supply chain verification, and failure analysis. IC packaging technologies and sample preparation techniques for die recovery and live analysis. Deprocessing and staining methods for revealing features bellow top passivation. Memory technologies and appropriate extraction techniques for each. Study contemporary anti-tamper/anti-RE methods and their effectiveness at protecting designs from attackers. Programmable logic microarchitecture and the issues involved with reverse engineering programmable logic.

  * [CSCI 4974/6974 - Spring '14 Hardware Reverse Engineering](http://security.cs.rpi.edu/courses/hwre-spring2014/)

####  City College of San Francisco - Sam Bowne Class

  * [CNIT 120 - Network Security](https://samsclass.info/120/120_S15.shtml) <br>
Knowledge and skills required for Network Administrators and Information Technology professionals to be aware of security vulnerabilities, to implement security measures, to analyze an existing network environment in consideration of known security threats or risks, to defend against attacks or viruses, and to ensure data privacy and integrity. Terminology and procedures for implementation and configuration of security, including access control, authorization, encryption, packet filters, firewalls, and Virtual Private Networks (VPNs).

  * [CNIT 121 - Computer Forensics](https://samsclass.info/121/121_S15.shtml) <br>
The class covers forensics tools, methods, and procedures used for investigation of computers, techniques of data recovery and evidence collection, protection of evidence, expert witness skills, and computer crime investigation techniques. Includes analysis of various file systems and specialized diagnostic software used to retrieve data. Prepares for part of the industry standard certification exam, Security+, and also maps to the Computer Investigation Specialists exam.

  * [CNIT 123 - Ethical Hacking and Network Defense](https://samsclass.info/123/123_S15.shtml) <br>
Students learn how hackers attack computers and networks, and how to protect systems from such attacks, using both Windows and Linux systems. Students will learn legal restrictions and ethical guidelines, and will be required to obey them. Students will perform many hands-on labs, both attacking and defending, using port scans, footprinting, exploiting Windows and Linux vulnerabilities, buffer overflow exploits, SQL injection, privilege escalation, Trojans, and backdoors.

  * [CNIT 124 - Advanced Ethical Hacking](https://samsclass.info/124/124_F15.shtml) <br>
Advanced techniques of defeating computer security, and countermeasures to protect Windows and Unix/Linux systems. Hands-on labs include Google hacking, automated footprinting, sophisticated ping and port scans, privilege escalation, attacks against telephone and Voice over Internet Protocol (VoIP) systems, routers, firewalls, wireless devices, Web servers, and Denial of Service attacks.

  * [CNIT 126 - Practical Malware Analysis](https://samsclass.info/126/126_F14.shtml) <br>
Learn how to analyze malware, including computer viruses, trojans, and rootkits, using disassemblers, debuggers, static and dynamic analysis, using IDA Pro, OllyDbg and other tools.

  * [CNIT 127 - Exploit Development](https://samsclass.info/127/127_F15.shtml) <br>
Learn how to find vulnerabilities and exploit them to gain control of target systems, including Linux, Windows, Mac, and Cisco. This class covers how to write tools, not just how to use them; essential skills for advanced penetration testers and software security professionals.

  * [CNIT 128 - Hacking Mobile Devices](https://samsclass.info/128/128_S15.shtml) <br>
Mobile devices such as smartphones and tablets are now used for making purchases, emails, social networking, and many other risky activities. These devices run specialized operating systems have many security problems. This class will cover how mobile operating systems and apps work, how to find and exploit vulnerabilities in them, and how to defend them. Topics will include phone call, voicemail, and SMS intrusion, jailbreaking, rooting, NFC attacks, malware, browser exploitation, and application vulnerabilities. Hands-on projects will include as many of these activities as are practical and legal.

  * [Violent Python and Exploit Development](https://samsclass.info/127/127_WWC_2014.shtml) <br>
 In the exploit development section, students will take over vulnerable systems with simple Python scripts. 

Laboratories
============

#### Pentester Lab
There is only one way to properly learn web penetration testing: by getting your hands dirty. We teach how to manually find and exploit vulnerabilities. You will understand the root cause of the problems and the methods that can be used to exploit them. Our exercises are based on common vulnerabilities found in different systems. The issues are not emulated. We provide you real systems with real vulnerabilities.

  * [From SQL Injection to Shell](https://pentesterlab.com/exercises/from_sqli_to_shell) <br>
This exercise explains how you can, from a SQL injection, gain access to the administration console. Then in the administration console, how you can run commands on the system.

  * [From SQL Injection to Shell: PostgreSQL edition](https://pentesterlab.com/exercises/from_sqli_to_shell_pg_edition) <br>
This exercise explains how you can from a SQL injection gain access to the administration console. Then in the administration console, how you can run commands on the system.

  * [From SQL Injection to Shell II](https://pentesterlab.com/exercises/from_sqli_to_shell_II) <br>
This exercise explains how you can, from a blind SQL injection, gain access to the administration console. Then in the administration console, how you can run commands on the system.

  * [Web for Pentester](https://pentesterlab.com/exercises/web_for_pentester) <br>
This exercise is a set of the most common web vulnerabilities.

  * [Web for Pentester II](https://pentesterlab.com/exercises/web_for_pentester_II) <br>
This exercise is a set of the most common web vulnerabilities.

  * [PHP Include And Post Exploitation](https://pentesterlab.com/exercises/php_include_and_post_exploitation) <br>
This exercice describes the exploitation of a local file include with limited access. Once code execution is gained, you will see some post exploitation tricks.

  * [Linux Host Review](https://pentesterlab.com/exercises/linux_host_review) <br>
This exercice explains how to perform a Linux host review, what and how you can check the configuration of a Linux server to ensure it is securely configured. The reviewed system is a traditional Linux-Apache-Mysql-PHP (LAMP) server used to host a blog.

  * [Electronic Code Book](https://pentesterlab.com/exercises/ecb) <br>
This exercise explains how you can tamper with an encrypted cookies to access another user's account.

  * [Rack Cookies and Commands injection](https://pentesterlab.com/exercises/rack_cookies_and_commands_injection) <br>
After a short brute force introduction, this exercice explains the tampering of rack cookie and how you can even manage to modify a signed cookie (if the secret is trivial). Using this issue, you will be able to escalate your privileges and gain commands execution.

  * [XSS and MySQL FILE](https://pentesterlab.com/exercises/xss_and_mysql_file) <br>
This exercise explains how you can use a Cross-Site Scripting vulnerability to get access to an administrator's cookies. Then how you can use his/her session to gain access to the administration to find a SQL injection and gain code execution using it.

  * [Axis2 Web service and Tomcat Manager](https://pentesterlab.com/exercises/axis2_and_tomcat_manager) <br>
This exercice explains the interactions between Tomcat and Apache, then it will show you how to call and attack an Axis2 Web service. Using information retrieved from this attack, you will be able to gain access to the Tomcat Manager and deploy a WebShell to gain commands execution.

  * [Play Session Injection](https://pentesterlab.com/exercises/play_session_injection) <br>
This exercise covers the exploitation of a session injection in the Play framework. This issue can be used to tamper with the content of the session while bypassing the signing mechanism.

  * [Play XML Entities](https://pentesterlab.com/exercises/play_xxe) <br>
This exercise covers the exploitation of a XML entities in the Play framework. 

  * [CVE-2007-1860: mod_jk double-decoding](https://pentesterlab.com/exercises/cve-2007-1860) <br>
This exercise covers the exploitation of CVE-2007-1860. This vulnerability allows an attacker to gain access to unaccessible pages using crafted requests. This is a common trick that a lot of testers miss.

  * [CVE-2008-1930: Wordpress 2.5 Cookie Integrity Protection Vulnerability](https://pentesterlab.com/exercises/cve-2008-1930) <br>
This exercise explains how you can exploit CVE-2008-1930 to gain access to the administration interface of a Wordpress installation.

  * [CVE-2012-1823: PHP CGI](https://pentesterlab.com/exercises/cve-2012-1823) <br>
This exercise explains how you can exploit CVE-2012-1823 to retrieve the source code of an application and gain code execution.

  * [CVE-2012-2661: ActiveRecord SQL injection](https://pentesterlab.com/exercises/cve-2012-2661) <br>
This exercise explains how you can exploit CVE-2012-2661 to retrieve information from a database.

  * [CVE-2012-6081: MoinMoin code execution](https://pentesterlab.com/exercises/cve-2012-6081) <br>
This exercise explains how you can exploit CVE-2012-6081 to gain code execution. This vulnerability was exploited to compromise Debian's wiki and Python documentation website.

  * [CVE-2014-6271/Shellshock](https://pentesterlab.com/exercises/cve-2014-6271) <br>
This exercise covers the exploitation of a Bash vulnerability through a CGI.

#### Syracuse University's SEED
##### Developing Instructional Laboratories for Computer SEcurity EDucation
People learn from mistakes. In security education, we study mistakes that lead to software vulnerabilities. Studying mistakes from the past not only help students understand why systems are vulnerable, why a "seemly-benign" mistake can turn into a disaster, and why many security mechanisms are needed. More importantly, it also helps students learn the common patterns of vulnerabilities, so they can avoid making similar mistakes in the future. Moreover, using vulnerabilities as case studies, students can learn the principles of secure design, secure programming, and security testing. 

  * [Software Security Labs](http://www.cis.syr.edu/~wedu/seed/software_security.html) <br>
    These labs cover some of the most common vulnerabilties in general software. The labs show students how attacks work in exploiting these vulnerabilities.

  * [Network Security Labs](http://www.cis.syr.edu/~wedu/seed/network_security.html) <br>
    These labs cover topics on network security, ranging from attacks on TCP/IP and DNS to various network security technologies (Firewall, VPN, and IPSec).

  * [Web Security Labs](http://www.cis.syr.edu/~wedu/seed/web_security.html) <br>
    These labs cover some of the most common vulnerabilities in web applications. The labs show students how attacks work in exploiting these vulnerabilities. 

  * [System Security Labs](http://www.cis.syr.edu/~wedu/seed/system_security.html) <br>
    These labs cover the security mechanisms in operating system, mostly focusing on access control mechanisms in Linux. 

  * [Cryptography Labs](http://www.cis.syr.edu/~wedu/seed/cryptography.html) <br>
    These labs cover three essential concepts in cryptography, including secrete-key encryption, one-way hash function, and public-key encryption and PKI.

  * [All SEED Laboratories](http://www.cis.syr.edu/~wedu/seed/all_labs.html) <br>

#### Dr. Thorsten Schneiderâ€™s Binary Auditing
Learn the fundamentals of Binary Auditing. Know how HLL mapping works, get more inner file understanding than ever. Learn how to find and analyse software vulnerability. Dig inside Buffer Overflows and learn how exploits can be prevented. Start to analyse your first viruses and malware the safe way. Learn about simple tricks and how viruses look like using real life examples.

  * [Binary Auditing](http://www.binary-auditing.com/)

Capture the Flag
================

#### Vulnhub
We all learn in different ways: in a group, by yourself, reading books, watching/listening to other people, making notes or things out for yourself. Learning the basics & understanding them is essential; this knowledge can be enforced by then putting it into practice. 

Over the years people have been creating these resources and a lot of time has been put into them, creating 'hidden gems' of training material. However, unless you know of them, its hard to discover them.

So VulnHub was born to cover as many as possible, creating a catalogue of 'stuff' that is (legally) 'breakable, hackable & exploitable' - allowing you to learn in a safe environment and practise 'stuff' out.
When something is added to VulnHub's database it will be indexed as best as possible, to try and give you the best match possible for what you're wishing to learn or experiment with.

  * [Vulnhub Repository](https://www.vulnhub.com/)

#### CTF Write Ups
  * [CTF Resources](https://ctfs.github.io/resources/) <br>
  A general collection of information, tools, and tips regarding CTFs and similar security competitions.
  
  * [CTF write-ups 2015](https://github.com/ctfs/write-ups-2015) <br>
Wiki-like CTF write-ups repository, maintained by the community. (2015)

  * [CTF write-ups 2014](https://github.com/ctfs/write-ups-2014) <br>
Wiki-like CTF write-ups repository, maintained by the community. (2014)

  * [CTF write-ups 2013](https://github.com/ctfs/write-ups-2013) <br>
Wiki-like CTF write-ups repository, maintained by the community. (2013)

Open Security Books
===================

#### Crypto 101 - lvh
Comes with everything you need to understand complete systems such as SSL/TLS: block ciphers, stream ciphers, hash functions, message authentication codes, public key encryption, key agreement protocols, and signature algorithms.  Learn how to exploit common cryptographic flaws, armed with nothing but a little time and your favorite programming language. Forge administrator cookies, recover passwords, and even backdoor your own random number generator.

  * [ Crypto101](https://www.crypto101.io/)
  * [LaTeX Source](https://github.com/crypto101/book)

#### Reverse Engineering for Beginners - Dennis Yurichev
 This book offers a primer on reverse-engineering, delving into disassembly code-level reverse engineering and explaining how to decipher assembly language for those beginners who would like to learn to understand x86 (which accounts for almost all executable software in the world) and ARM code created by C/C++ compilers. 

  * [Reverse Engineering for Beginners](http://beginners.re/)
  * [LaTeX Source](https://github.com/dennis714/RE-for-beginners)

#### CTF Field Guide - Trail of Bits
The focus areas that CTF competitions tend to measure are vulnerability discovery, exploit creation, toolkit creation, and operational tradecraft.. Whether you want to succeed at CTF, or as a computer security professional, youâ€™ll need to become an expert in at least one of these disciplines. Ideally in all of them.

  * [CTF Field Guide](https://trailofbits.github.io/ctf/)
  * [Markdown Source](https://github.com/trailofbits/ctf)

Related Awesome Lists
=====================

  * [Awesome Pentest](https://github.com/enaqx/awesome-pentest) <br>
 A collection of awesome penetration testing resources, tools and other shiny things.

  * [Awesome Appsec](https://github.com/paragonie/awesome-appsec) <br>
A curated list of resources for learning about application security.

  * [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) <br>
 A curated list of awesome malware analysis tools and resources.
  
  * [Android Security Awesome](https://github.com/ashishb/android-security-awesome) <br>
A collection of android security related resources.

  * [Awesome CTF](https://github.com/apsdehal/awesome-ctf) <br>
A curated list of CTF frameworks, libraries, resources and softwares.

  * [Awesome Security](https://github.com/sbilly/awesome-security) <br>
 A collection of awesome software, libraries, documents, books, resources and cools stuffs about security.

  * [Awesome Honeypots](https://github.com/paralax/awesome-honeypots) <br>
A curated list of awesome honeypots, tools, components and much more.

  * [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools) <br>
A collection of tools developed by other researchers in the Computer Science area to process network traces. 

  * [Awesome Hacking](https://github.com/carpedm20/awesome-hacking) <br>
 A curated list of awesome Hacking tutorials, tools and resources.


[Contributing](https://github.com/onlurking/awesome-infosec/blob/master/contributing.md)
=====================

Pull requests and issues with suggestions are welcome!

License
=======

[![Creative Commons License](http://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).