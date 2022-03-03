Awesome Infosec
===============

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

受 GitHub 上的 awesome-* 仓库的启发，精心策划的信息安全资源列表

这些资源和工具仅用于受控环境下的网络安全专业和教育用途

目录
=================

1. [Massive Online Open Courses](#massive-online-open-courses)
2. [Academic Courses](#academic-courses)
3. [Laboratories](#laboratories)
4. [Capture the Flag](#capture-the-flag)
5. [Open Security Books](#open-security-books)
6. [Challenges](#challenges)
7. [Documentation](#documentation)
8. [SecurityTube Playlists](#securitytube-playlists)
9. [Related Awesome Lists](#related-awesome-lists)
10. [Contributing](#contributing)
11. [License](#license)

Massive Online Open Courses
===========================

#### 斯坦福大学 - 计算机安全
本课程旨在教授如何设计安全系统以及如何编写安全代码。可以学到如何查找代码中的漏洞以及如何限制软件系统中安全漏洞的影响。重点关注设计、建设安全系统的原则，并给出许多实例

- [Stanford University - Computer Security](https://www.coursera.org/learn/security)

#### 斯坦福大学 - 密码学 I
本课程旨在介绍密码学原型理论是如何工作的，以及如何正确的使用。学生将学习如何推断密码构成的安全性，以及如何将这些知识应用到实际应用中。本课程首先详细讨论了拥有共享密钥的双方如何在对手可以窃听并篡改流量时安全地进行通信。我们分析了许多已经部署使用的协议，并检查了现有系统中存在的问题。课程的后面讨论了多方产生共享密钥的公钥技术。课程涵盖相关数论，讨论公钥加密和基本的密钥交换过程。课程里学生可以接触到该领域内许多激动人心的问题。

- [Stanford University - Cryptography I](https://www.coursera.org/learn/crypto)

#### 斯坦福大学 - 密码学 II
本课程是密码学 I 的后续课程，解释了公钥系统和加密协议内部的工作原理。课程从数字签名及其应用讲起，然后讨论了用户认证协议与零知识协议。课程的后面讨论了加密技术在匿名凭据和隐私数据库查询上的应用。课程还包括了一些高级议题，包括多方计算和椭圆曲线

- [Stanford University - Cryptography II](https://www.coursera.org/learn/crypto2)

#### 马里兰大学 - Usable Security
本课程着眼于如何设计、建立以人为中心的安全系统。课程研究人机交互的基本原理，并将这些原理应用到安全系统的设计中，目标是设计符合系统内人员体验和系统建设目标的安全系统

- [University of Maryland - Usable Security](https://www.coursera.org/learn/usablesec)

#### 马里兰大学 - 软件安全
本课程旨在研究软件安全的基础。我们将讨论重要的软件漏洞以及如何利用这些漏洞执行攻击（如缓冲区溢出、SQL 注入与会话劫持等），我们将考虑防御或缓解这些攻击的措施。包括高级测试与程序分析技术，更重要的是，我们采取“构建安全”的思路，综合考虑可用于加强软件系统安全开发周期各个阶段的技术

- [University of Maryland - Software Security](https://www.coursera.org/learn/softwaresec)

#### 马里兰大学 - 密码学
本课程旨在介绍现代密码学的基础与实际应用。我们将会讨论界定安全的重要性，主要依靠一套经过深入研究的“硬度假设”以及基于低级原型的复杂结构安全的可能性。我们不但在理论上对这些思想进行讲解，还会探索其现实影响。课程中会介绍被广泛使用的密码学原型，并了解如何将这些原型结合起来用于开发通信安全的现代协议

- [University of Maryland - Cryptography](https://www.coursera.org/learn/cryptography)

#### 马里兰大学 - 硬件安全
本课程旨在介绍现代密码学的基础与实际应用。我们将会讨论界定安全的重要性，主要依靠一套经过深入研究的“硬度假设”以及基于低级原型的复杂结构安全的可能性。我们不但在理论上对这些思想进行讲解，还会探索其现实影响。课程中会介绍被广泛使用的密码学原型，并了解如何将这些原型结合起来用于开发通信安全的现代协议

- [University of Maryland - Hardware Security](https://www.coursera.org/learn/hardwaresec)

Academic Courses
================

#### NYU Tandon School of Engineering - OSIRIS Lab's Hack Night

Hack Night 是基于 NYU Tandon 的渗透测试和漏洞分析课程的资料开发的，是对安全中攻击的一个全面介绍。学生在十三周内会接触到各种各样的复杂和身临其境的问题，很多复杂的技术内容都覆盖在内

- [NYU Tandon's OSIRIS Lab's Hack Night](https://github.com/isislab/Hack-Night)

#### 佛罗里达州立大学 - Offensive Computer Security
攻击者利用漏洞发动进攻的主要动机是获得投资回报（主要是时间投入），这个回报不一定是货币，攻击者可能对数据或其他对攻击者有价值的信息感兴趣。渗透测试涉及对系统进行授权地审计和利用，以评估实际系统的安全性来阻止攻击者。这需要深入了解漏洞以及知道如何利用漏洞。因此，本课程提供了白帽子渗透测试和安全系统管理所使用的基本方法、技能、法律问题和对工具简单却全面的介绍

 * [Offensive Computer Security - Spring 2014](http://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity)
 * [Offensive Computer Security - Spring 2013](http://www.cs.fsu.edu/~redwood/OffensiveSecurity)

#### 佛罗里达州立大学 - Offensive Network Security
本课程旨在帮助学生深入了解已知的协议（IP、TCP、UDP），以及攻击者是如何利用这些协议进行攻击、如何通过捕获的网络流量来发现网络中存在的问题。本课程的前半部分侧重于协议知识，而后半部分侧重于逆向未知协议。课程利用捕获的流量，让学生通过已知的技术，如 Marshall Beddoe 引入的 bioinformatics 来逆向协议。课程还涵盖对协议的模糊测试（查看服务器或者客户端是否存在漏洞）。总的来说，这门课程引导学生更好地理解计算机网络中的协议、通信、交互等概念

 * [Offensive Network Security](http://www.cs.fsu.edu/~lawrence/OffNetSec/)

#### 伦斯勒理工学院 - Malware Analysis
本课程向学生介绍现代恶意软件分析技术，通过对实际样本的阅读和实验分析，让学生了解静态、动态分析现代高级恶意软件的技术

- [CSCI 4976 - Fall '15 Malware Analysis](https://github.com/RPISEC/Malware)

#### 伦斯勒理工学院 - Modern Binary Exploitation
本课程首先介绍基本的 x85 逆向工程、漏洞分析和基于 Linux 的用户级二进制利用的经典样例。然后讲解现代系统上保护与缓解这些攻击手段的技术（如 Canaries、DEP、ASLR、RELRO、Fortify Source 等）。课程还涵盖内核利用与基于 Windows 系统的利用

* [CSCI 4968 - Spring '15 Modern Binary Exploitation](https://github.com/RPISEC/MBE)

#### 伦斯勒理工学院 - 硬件逆向工程
半导体器件的逆向工程技术常用于分析竞品、知识产权诉讼、安全测试、供应链验证与失效分析。研究现代防篡改/反逆向工程方法以及在阻止攻击者方面的有效性。还包括一些可编程逻辑微体系结构和逆向工程可编程逻辑时涉及的问题

- [CSCI 4974/6974 - Spring '14 Hardware Reverse Engineering](http://security.cs.rpi.edu/courses/hwre-spring2014/)

####  旧金山城市学院 - Sam Bowne 课程

- [CNIT 40: DNS 安全](https://samsclass.info/40/40_F16.shtml)<br>
DNS 对于所有的互联网用户而言都是至关重要的，它会遇到很多的安全风险，包括网络钓鱼、DNS 劫持、数据包放大、欺骗、中毒等。了解如何配置安全的 DNS 服务器，并通过 DNS 来监控、检测恶意活动。我们还涵盖了 DNSSEC 原则和部署。学生会在 Windows 和 Linux 平台上部署安全 DNS 服务器

- [CNIT 120 - 网络安全](https://samsclass.info/120/120_S15.shtml)<br>
网络管理员和 IT 从业人员都需要了解安全漏洞的知识和技能。如何实施安全措施，如何考虑已知安全威胁或风险来分析现有网络环境，防御网络攻击或病毒，如何确保数据的隐私性和完整性。包括访问控制、授权、加密、数据包过滤、防火墙和 VPN 在内的安全实施与配置程序

- [CNIT 121 - 计算机取证](https://samsclass.info/121/121_F16.shtml)<br>
本课程旨在讲授用于调查计算机的取证工具，以及如何恢复数据、证据收集、证据保护等计算机犯罪调查技术。包括用于检索数据的各种文件系统和专用诊断软件的分析。课程内容有一部分可以用于准备工业标准认证考试、Security+ 与计算机调查专家考试

- [CNIT 123 - 黑客入侵与网络防御](https://samsclass.info/123/123_S17.shtml)<br>
本课程学习如何攻击计算机与网络，以及如何使用 Windows 和 Linux 系统来免受此类攻击。课程还包括法律限制和道德准则。课上会综合学习端口扫描、Windows/Linux 系统漏洞利用、缓冲区溢出攻击、SQL 注入、提权、木马和后门等

- [CNIT 124 - 高级黑客入侵](https://samsclass.info/124/124_F15.shtml)<br>
更高级的计算机安全技术，动手尝试 Google Hacking、复杂的端口扫描、提权、针对网络电话（VoIP）、路由器、防火墙、无线设备、Web 服务器以及拒绝服务的攻击

- [CNIT 126 - 实践恶意软件分析](https://samsclass.info/126/126_S16.shtml)<br>
了解如何使用反汇编、调试器、静态分析、动态分析，使用 IDA Pro、OllyDbg 和其他工具来分析恶意软件，包括计算机病毒、木马和 Rootkit

- [CNIT 127 - 漏洞利用开发](https://samsclass.info/127/127_S17.shtml)<br>
了解如何发现漏洞以及如何利用漏洞获取对目标系统（包括 Windows、Mac、Linux 和 Cisco）的控制权。课程包括了如何编写工具，而不仅仅是利用它们。这是高级渗透测试人员和软件安全专业人员的基本技能

- [CNIT 128 - 入侵移动设备](https://samsclass.info/128/128_S17.shtml)<br>
智能手机和平板电脑等移动设备越来越普及，这些设备运行的操作系统有很多安全问题。本课程将介绍移动操作系统和应用程序的工作方式，以及如何发现与利用其中的漏洞。其中包括电话、语音邮件、短信入侵、越狱、root、NFC 攻击、恶意软件、浏览器利用与应用程序漏洞

- [CNIT 129S: 增强 Web 应用程序安全](https://samsclass.info/129S/129S_F16.shtml)<br>
课程讲授攻击者常用的技术，以及如何进行防御。如何保护身份验证、如何保护数据库和后端组件。如何保护用户免受彼此的影响。如果在源代码和程序冲找到常见的漏洞

- [CNIT 140: IT 安全实践](https://samsclass.info/140/140_F16.shtml)<br>
为信息安全竞赛（CTF 与 [Collegiate Cyberdefense Competition (CCDC)](http://www.nationalccdc.org/)）的培训，这种培训将为专业人员的就业做准备，如果我们的团队在竞争中取得好成绩，竞争对手会认可并尊重，从而提供更多更好的工作机会

- [暴力的 Python 与漏洞利用开发](https://samsclass.info/127/127_WWC_2014.shtml)<br>
用简单的 Python 脚本来攻陷易受攻击的系统

## Open Security Training
OpenSecurityTraining.info 致力于共享计算机安全类培训资料

#### 初学入门

- [Android Forensics & Security Testing](http://opensecuritytraining.info/AndroidForensics.html)<br>
该课程旨在移动平台上的数字取证，包括 Android 操作系统取证以及 Android 应用程序渗透测试的基础

- [Certified Information Systems Security Professional (CISSP)® <br>Common Body of Knowledge (CBK)® Review](http://opensecuritytraining.info/CISSP-Main.html)<br>
CISSP CBK 回顾课程为联邦机构信息认证（IA）专家专门设计的，符合 [NSTISSI-4011](http://www.cnss.gov/Assets/pdf/nstissi_4011.pdf) 与 [DoD 8570.01-M](http://www.dtic.mil/whs/directives/corres/pdf/857001m.pdf)

- [Flow Analysis & Network Hunting](http://opensecuritytraining.info/Flow.html)<br>
课程旨在从 SOC 的角度对网络分析和恶意活动进行探索。我们将深入分析网络流量的优势和限制，探讨传感器的布置、网络流量工具、网络数据可视化、网络态势感知与网络狩猎

- [Hacking Techniques and Intrusion Detection](http://opensecuritytraining.info/HTID.html)<br>
本课程旨在深入介绍黑客技术与入侵检测领域的高级主题

- [Introductory Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntroX86.html)<br>
讲授了 x86 的基本概念并描述了处理汇编代码的硬件。覆盖了许多常见的汇编指令。虽然 x86 有数百个不同用途的指令，但是通常来说掌握 20-30 条指令及其变体就能读懂大部分程序

- [Introduction to ARM](http://opensecuritytraining.info/IntroARM.html)<br>
课程建立在 x86 的基础上，尽可能提供两个体系结构中的异同，同时关注 ARM 指令集和一些 ARM 处理器的功能，以及如何在 ARM 上运行的

- [Introduction to Cellular Security](http://opensecuritytraining.info/IntroCellSec.html)<br>
本课程旨在演示蜂窝网络安全的核心概念。虽然课程讨论的是 GSM、UMTS 和 TLE，但主要关注的是 LTE。课程首先介绍了有关蜂窝网络的重要概念，然后跟随 GSM 一路演进到 LTE

- [Introduction to Network Forensics](http://opensecuritytraining.info/NetworkForensics.html)<br>
本课程旨在讲授网络监控和数字取证技术

- [Introduction to Secure Coding](http://opensecuritytraining.info/IntroSecureCoding.html)<br>
本课程介绍了业内最流行的安全相关编码错误，深入解释了每种类型的错误，包括攻击者如何对代码进行攻击，并回顾了避免这些问题的策略

- [Introduction to Vulnerability Assessment](http://opensecuritytraining.info/IntroductionToVulnerabilityAssessment.html)<br>
本课程介绍了一些常见的通用计算技术的漏洞评估，还演示了特定的工具和技术

- [Introduction to Trusted Computing](http://opensecuritytraining.info/IntroToTrustedComputing.html)<br>
本课程旨在介绍可信计算背后的技术。将了解什么是可信平台模块（TPM）以及更深入的技术层面和企业环境中提供哪些功能。课程还涵盖了其他技术（如动态信任根机制（DRTM）和虚拟化），如何利用 TPM 并用于提高 TPM

- [Offensive, Defensive, and Forensic Techniques for Determining Web User Identity](http://opensecuritytraining.info/WebIdentity.html)<br>
本课程从几个不同的角度来看 Web 用户。首先讨论了从服务器角度确定 Web 用户身份的技术。其次讨论了试图匿名用户的角度如何看待混淆技术。最后介绍了取证技术，在给予硬盘驱动器或类似媒体时，我们可以确定访问该服务器的用户

- [Pcap Analysis & Network Hunting](http://opensecuritytraining.info/Pcap.html)<br>
解释了如何捕获网络流量以及如何处理网络流量。本课程涵盖了多个开源工具：tcpdump、Wireshark 和 ChopShop。包括如何使用 tcpdump 捕获数据包，仅使用命令行工具挖掘 DNS 解析以及清除混淆的协议

- [Malware Dynamic Analysis](http://opensecuritytraining.info/MalwareDynamicAnalysis.html)<br>
刚开始从事恶意软件分析工作的人员用来学习恶意软件动态分析，该课程是一个动手实践的课程，学生通过使用各种工具来查找恶意软件

- [Secure Code Review](http://opensecuritytraining.info/SecureCodeReview.html)<br>
本课程旨在介绍开发生命周期以及同行评审在提高产品质量上的重要性。讨论了如何进行同行评审，并强调了在评审过程中如何保证安全编码。各种实践帮助练习解决常见的编码错误以及在审查过程中应重点关注什么，还有如何管理有限的时间

- [Smart Cards](http://opensecuritytraining.info/SmartCards.html)<br>
展示了与其他类型的卡相比，智能卡的不同之处。它解释了如何使用智能卡来实现信息的机密性和完整性

- [The Life of Binaries](http://opensecuritytraining.info/LifeOfBinaries.html)<br>
我们讨论程序不同阶段的安全性，从编译器开始，攻击者可以利用的技巧，病毒是如何工作的，以及恶意软件如何复制操作系统过程，与带有空间地址布局随机化（ASLR）安全性增强的 OS 加载器的好处

- [Understanding Cryptology: Core Concepts](http://opensecuritytraining.info/CryptoCore.html)<br>
对密码学的介绍，重点是应用密码学

- [Understanding Cryptology: Cryptanalysis](http://opensecuritytraining.info/Cryptanalysis.html)<br>
本课程介绍了各种破译密码的技巧和 Python 实验，值得注意的是本课程中包含很多数学知识

#### 中级课程

- [Exploits 1: Introduction to Software Exploits](http://opensecuritytraining.info/Exploits1.html)<br>
软件漏洞是程序逻辑中的漏洞，攻击者可以利用这些漏洞在目标系统上执行任意代码。本课程将涵盖软件漏洞的识别和利用技术，此外还将讨论缓解软件漏洞利用的技术

- [Exploits 2: Exploitation in the Windows Environment](http://opensecuritytraining.info/Exploits2.html)<br>
本课程介绍 Windows 环境下漏洞利用的情况，Windows 下的漏洞利用涉及到许多细微之处，Windows 下还有许多漏洞利用缓解措施，例如 DEP、ASLR、SafeSEH 和 SEHOP，这些措施都使得编写漏洞利用代码更加困难

- [Intermediate Intel x86: Architecture, Assembly, Applications, & Alliteration](http://opensecuritytraining.info/IntermediateX86.html)<br>
基于 x86 的入门级，本课程将深入讨论已学习的主题，并更深入的了解英特尔的系统如何工作

#### 高级课程

- [Advanced x86: Virtualization with Intel VT-x](http://opensecuritytraining.info/AdvancedX86-VTX.html)<br>
本课程介绍英特尔硬件支持的虚拟化，第一部分介绍在没有专用硬件的情况下虚拟化的挑战，随后深入了解英特尔虚拟化 API 和英特尔实验室的“蓝色药丸”/“超级劫持”攻击，最后讨论了虚拟化检测技术

- [Advanced x86: Introduction to BIOS & SMM](http://opensecuritytraining.info/IntroBIOS.html)<br>
本课程介绍 BIOS 为什么对平台的安全至关重要。当 BIOS 没有得到适当保护时，攻击者得到了哪些机会？课程还将介绍用于执行固件漏洞分析以及固件取证的工具。这门课教授现有的逆向工程技术人员如何分析 UEFI 固件，这同样可以用于漏洞发现，也可以用来分析在 BIOS 中发现的可疑植入物

- [Introduction to Reverse Engineering Software](http://opensecuritytraining.info/IntroductionToReverseEngineering.html)<br>
纵观工具发明史，人类总是好奇地要去理解其内部工作原理。无论是调查一块破损的手表还是改进发动机，这些人都把物品分解成各个要素以了解它们是如何工作的。这就是逆向工程（RE），试图理解恶意代码、利用软件中的缺陷

- [Reverse Engineering Malware](http://opensecuritytraining.info/ReverseEngineeringMalware.html)<br>
本课程以[介绍软件逆向工程](http://opensecuritytraining.info/IntroductionToReverseEngineering.html) 为开场，探讨如何使用静态逆向工程来了解恶意软件的工作原理以及如何将其清除

- [Rootkits: What they are, and how to find them](http://opensecuritytraining.info/Rootkits.html)<br>
Rootkits 是一类专门用于隐藏受感染系统中的攻击者的恶意软件。本课程将着重了解 Rootkit 是如何工作的，以及使用哪些工具可以找到它们

- [The Adventures of a Keystroke: An in-depth look into keylogging on Windows](http://opensecuritytraining.info/Keylogging.html)<br>
键盘记录器是恶意软件中使用最广泛的组件之一，如果有人可以记录你的击键，那么他可以在你没有防备的情况下控制你的整个电脑


## Cybrary - Online Cyber Security Training

- [CompTIA A+](https://www.cybrary.it/course/comptia-aplus)<br>
课程涵盖了计算机技术、基本网络概念、PC、笔记本电脑和相关硬件的安装和配置的基础知识，以及移动操作系统 Android 和 Apple iOS 配置常用功能

- [CompTIA Linux+](https://www.cybrary.it/course/comptia-linux-plus)<br>
免费、自学的在线 Linux+ 培训为学生提供了成为认证 Linux+ 专家的知识，涵盖了涵盖 Linux 维护任务、用户帮助、安装和配置等任务

- [CompTIA Cloud+](https://www.cybrary.it/course/comptia-cloud-plus)<br>
Cloud+ 培训解决了尽可能安全地实施、管理和维护云技术的基本知识。它涵盖了云中模型、虚拟化和基础架构等概念

- [CompTIA Network+](https://www.cybrary.it/course/comptia-network-plus)<br>
主要是构建一个网络技能套件

- [CompTIA Advanced Security Practitioner](https://www.cybrary.it/course/comptia-casp)<br>
CompTIA CASP 培训中，将学习到如何集成高级认证、如何管理企业风险、如何进行漏洞评估以及如何分析网络安全概念和组件

- [CompTIA Security+](https://www.cybrary.it/course/comptia-security-plus)<br>
了解一般安全性概念、密码学基础知识、通信安全性以及操作和组织安全性

- [ITIL Foundation](https://www.cybrary.it/course/itil)<br>
课程提供了 IT 服务管理最佳实践的基本知识：如何降低成本，提高流程改进，提高 IT 生产力和整体客户满意度

- [Cryptography](https://www.cybrary.it/course/cryptography)<br>
课程研究密码学是如何成为安全技术的基石，以及如何通过使用不同的加密方法来保护私人或敏感信息免受未经授权的访问

- [Cisco CCNA](https://www.cybrary.it/course/cisco-ccna)<br>
CCNA 培训课程为中型网络安装，配置，故障排除和操作 LAN、WAN 和拨号接入服务

- [Virtualization Management](https://www.cybrary.it/course/virtualization-management)<br>
课程重点在于安装，配置和管理虚拟化软件、如何在云环境中工作以及如何为其构建基础架构

- [Penetration Testing and Ethical Hacking](https://www.cybrary.it/course/ethical-hacking)<br>
课程可以学习如何以攻击者的方式利用网络，以便了解如何保护系统免受攻击

- [Computer and Hacking Forensics](https://www.cybrary.it/course/computer-hacking-forensics-analyst)<br>
课程可以学习如何确定潜在的网络犯罪活动，合法收集证据，搜索和调查无线攻击

- [Web Application Penetration Testing](https://www.cybrary.it/course/web-application-pen-testing)<br>
中小型企业 Raymond Evans 带领您进入 Web 应用程序渗透测试的迷人之旅，该实验非常强调动手能力，要求自己配置试验环境

- [CISA - Certified Information Systems Auditor](https://www.cybrary.it/course/cisa)<br>
为了面对满足企业漏洞管理挑战的动态需求，本课程涵盖审核流程，以确保您有能力分析组织状态并在需要时进行更改

- [Secure Coding](https://www.cybrary.it/course/secure-coding)<br>
课程讨论安全编码指南以及安全编码在降低风险和漏洞方面的重要性。了解 XSS、直接对象引用、数据暴露、缓冲区溢出和资源管理

- [NIST 800-171 Controlled Unclassified Information Course](https://www.cybrary.it/course/nist-800-171-controlled-unclassified-information-course)<br>
课程涵盖了在非联邦机构中保护受控未分类信息的 14 个领域。为NIST 800-171 特殊出版物中定义的每个安全域提供基本要求和派生要求

- [Advanced Penetration Testing](https://www.cybrary.it/course/advanced-penetration-testing)<br>
如何利用跨站点脚本攻击、SQL注入攻击、远程和本地文件包含以及如何理解您正在攻击的网络的防御者

- [Intro to Malware Analysis and Reverse Engineering](https://www.cybrary.it/course/malware-analysis)<br>
课程讲授如何对所有主要文件类型执行动态和静态分析，如何从文档中分离恶意可执行文件，如何识别常见恶意软件策略以及如何调试和反汇编恶意二进制文件

- [Social Engineering and Manipulation](https://www.cybrary.it/course/social-engineering)<br>
课程介绍了如何进行社会工程攻击，以及在攻击中每个步骤中所做的事情

- [Post Exploitation Hacking](https://www.cybrary.it/course/post-exploitation-hacking)<br>
后渗透测试主要涉及三个主要主题：信息收集、后门和覆盖步骤，如何使用系统特定工具来获取常规信息，监听 Shell，metasploit 和 meterpreter 脚本

- [Python for Security Professionals](https://www.cybrary.it/course/python)<br>
本课程在十几个小时从基本概念到高级脚本，重点关注网络与安全

- [Metasploit](https://www.cybrary.it/course/metasploit)<br>
这个免费的 Metasploit 培训课程将教您利用 Metasploit 的深入功能进行渗透测试，并帮助您为任何规模的组织运行漏洞评估

- [ISC2 CCSP - Certified Cloud Security Professional](https://www.cybrary.it/course/isc2-certified-cloud-security-professional-ccsp)<br>
现实情况是，攻击者从不休息，而且随着针对内部网络和系统的传统威胁，出现了专门针对云计算的全新变种

**Executive**

- [CISSP - 认证信息系统安全专家](https://www.cybrary.it/course/cissp)<br>
免费在线 CISSP（8 个领域）培训涵盖了运行、电信、网络和互联网安全、访问控制系统、业务连续性等主题

- [CISM - 认证信息安全经理](https://www.cybrary.it/course/cism)<br>
该课程非常适合希望那个在组织中提升自己的职业或者目前就是 CISM 的 IT 人员

- [PMP - 项目管理专家](https://www.cybrary.it/course/project-management-professional)<br>
免费的 PMP 培训课程将教授如何启动、计划与管理项目、项目风险分析、监测控制项目合同、制定项目时间表和预算

- [CRISC - Certified in Risk and Information Systems Control](https://www.cybrary.it/course/crisc)<br>
认证风险和信息系统控制认证适用于开发和维护信息系统控制的IT和业务专业人员，其工作围绕安全操作和合规性展开

- [Risk Management Framework](https://www.cybrary.it/course/risk-management-framework)<br>
美国国家标准与技术研究院（NIST）将风险管理框架（RMF）设置为美国政府机构为确保其数据系统的合规性而必须遵循的一套操作和程序标准或准则

- [ISC2 CSSLP - Certified Secure Software Life-cycle Professional](https://www.cybrary.it/course/csslp-training)<br>
如何在组织内推进建设保证安全软件生命周期，以及如何应用最佳实践来保持系统良好运行

- [COBIT - Control Objectives for Information and Related Technologies](https://www.cybrary.it/course/cobit)<br>
Cybrary 的在线 COBIT 认证计划提供了一个学习 COBIT 5 框架所有组件的机会，涵盖了业务端到端如何有效管理企业 IT 的策略

- [Corporate Cybersecurity Management](https://www.cybrary.it/course/corporate-cybersecurity-management)<br>
网络风险、法律考虑往往被企业所忽视，如果发生事故就会造成重大财务损失

## Hopper's Roppers 
- [Learning How to Learn How to Hack](https://hoppersroppers.github.io/course.html)<br>
免费、自定义进度的课程，在计算机与网络方面介绍基本知识，本课程旨在培养没有先验知识的学生

Laboratories
============

## Syracuse University's SEED

### 安全教育实验室

 SEED 项目始于 2002 年，由 NSF 资助共计 130 万美元，目前全世界有数百所教育机构使用，SEED 项目的目标是开发用于计算机和信息安全教育实验室中的练习

### 软件安全实验室

这些实验室涵盖了一般软件中最常见的一些漏洞，这些实验展示攻击如何利用这些漏洞进行攻击

- [缓冲区溢出漏洞实验室](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Buffer_Overflow)<br>
利用 Shellcode 来利用缓冲区溢出漏洞，几种对策进行实验

- [Return-to-libc 攻击实验室](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Return_to_libc)<br>
使用 return-to-libc 技术来应对缓解缓冲区溢出攻击的非可执行栈

- [环境变量与 Set-UID 实验室](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Environment_Variable_and_SetUID)<br>
Set-UID 实验室的重新设计

- [Set-UID 程序漏洞实验室](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Set-UID)<br>
对特权 Set-UID 程序的攻击

- [Race-Condition Vulnerability Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Race_Condition)<br>
利用特权程序中的竞态条件漏洞

- [Format-String Vulnerability Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Format_String)<br>
利用格式字符串漏洞可以使程序崩溃，窃取敏感信息或修改关键数据

- [Shellshock Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Shellshock)<br>
2014 年发现的 Shellshock 漏洞的实验室


### Network Security Labs
 这些实验包括对 TCP/IP 和 DNS 攻击到各种网络安全技术（防火墙、VPN 和 IPSec）

- [TCP/IP 攻击实验室](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/TCPIP)<br>
利用 TCP/IP 协议的漏洞发起攻击，包括会话劫持、SYN 洪泛、TCP 重置攻击

- [Heartbleed Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Heartbleed)<br>
利用 Heartbleed 漏洞从远程服务器窃取秘密信息

- [Local DNS Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/DNS_Local)<br>
使用多种方法在局域网环境中对计算机进行 DNS 欺骗攻击

- [Remote DNS Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/DNS_Remote)<br>
使用 Kaminsky 方法在远程 DNS 服务器上启动 DNS 缓存中毒攻击

- [Packet Sniffing and Spoofing Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Sniffing_Spoofing)<br>
编写程序来嗅探通过本地网络发送的数据包，编写程序来欺骗各种类型的数据包

- [Linux Firewall Exploration Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_Linux)<br>
编写一个简单的包过滤防火墙，使用 Linux 内置的防火墙软件和 Web 代理防火墙，试验逃避防火墙的方法

- [Firewall-VPN Lab: Bypassing Firewalls using VPN](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_VPN)<br>
使用一个简单的 VPN 程序（客户端/服务器），并用它绕过防火墙

- [Virtual Private Network (VPN) Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/VPN)<br>
使用 TUN/TAP技术为 Linux 设计和实现传输层 VPN 系统，通常这个项目至少需要一个月的时间才能完成

- [Minix IPSec Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/IPSec)<br>
在 Minix 操作系统中实施 IPSec 协议，并使用它来建立 VPN

- [Minix Firewall Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Networking/Firewall_Minix)<br>
在 Minix 操作系统中实现一个简单的防火墙

### Web Security Labs
 这些实验包含了一些 Web 应用程序中最常见的漏洞。这些实验展示了如何利用这些漏洞进行攻击

#### Elgg-Based Labs
Elgg 是一个开源的社交网络系统，为了实验进行了一些修改

- [Cross-Site Scripting Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Web/Web_XSS_Elgg)<br>
对易受攻击的 Web 应用程序启动跨站点脚本攻击

- [Cross-Site Request Forgery Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Web/Web_CSRF_Elgg)<br>
对易受攻击的 Web 应用程序发起跨站请求伪造攻击

- [Web Tracking Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Web/Web_Tracking_Elgg)<br>
实验 Web 跟踪技术

- [SQL Injection Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Web/Web_SQL_Injection)<br>
在易受攻击的 Web 应用程序上发起 SQL 注入攻击

#### Collabtive-Based Labs
Collabtive 是一个开源的 Web 项目管理系统，为了实验做了修改

- [Cross-site Scripting Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Web/XSS_Collabtive)<br>
对易受攻击的 Web 应用程序启动跨站点脚本攻击

- [Cross-site Request Forgery Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Web/CSRF_Collabtive)<br>
对易受攻击的 Web 应用程序发起跨站请求伪造攻击

- [SQL Injection Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Web/SQL_Injection_Collabtive)<br>
在易受攻击的 Web 应用程序上发起 SQL 注入攻击

- [Web Browser Access Control Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Web/Web_SOP_Collabtive)<br>
探索浏览器的访问控制系统来理解其安全策略

#### PhpBB-Based Labs
PhpBB 是一个开源的 Web 留言板系统，允许用户发布消息，为了实验做了修改

- [Cross-site Scripting Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Attacks_XSS)<br>
对易受攻击的 Web 应用程序启动跨站点脚本攻击

- [Cross-site Request Forgery Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Attacks_CSRF)<br>
对易受攻击的 Web 应用程序发起跨站请求伪造攻击

- [SQL Injection Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Attacks_SQL_Injection)<br>
在易受攻击的 Web 应用程序上发起 SQL 注入攻击

- [ClickJacking Attack Lab](http://www.cis.syr.edu/~wedu/seed/Labs/Vulnerability/ClickJacking)<br>
在易受攻击的网站上发起 ClickJacking 攻击

### System Security Labs
这些实验包括操作系统中的安全机制，主要集中在 Linux 的访问控制机制上

- [Linux Capability Exploration Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/System/Capability_Exploration)<br>
探索 Linux 中的 POSIX 1.e 系统，了解如何将特权划分为更小的部分以确保符合最低特权原则

- [Role-Based Access Control (RBAC) Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/System/RBAC_Cap)<br>
为 Minix 设计并实现一个集成的访问控制系统，该系统使用基于能力和基于角色的访问控制机制，需要修改 Minix 内核

- [Encrypted File System Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/System/EFS)<br>
为 Minix 设计和实现加密文件系统，需要修改 Minix 内核

### Cryptography Labs
实验包括密码学中的三个基本概念，包括密钥加密、单向散列函数、公钥加密和 PKI

- [Secret Key Encryption Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Crypto/Crypto_Encryption)<br>
探索使用 OpenSSL 的密钥加密及其应用

- [One-Way Hash Function Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Crypto/Crypto_Hash)<br>
探索使用 OpenSSL 的单向散列函数及其应用

- [Public-Key Cryptography and PKI Lab](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Crypto/Crypto_PublicKey)<br>
使用 OpenSSL 探索公钥加密、数字签名、证书和 PKI

### Mobile Security Labs
这些实验专注于智能手机的安全性，涵盖了移动设备上最常见的漏洞和攻击。这些实验提供了 Android VM

- [Android Repackaging Lab](http://www.cis.syr.edu/~wedu/seed/Labs_Android5.1/Android_Repackaging)<br>
将恶意代码插入现有的 Android 应用程序中，然后重新打包

- [Android Device Rooting Lab](http://www.cis.syr.edu/~wedu/seed/Labs_Android5.1/Android_Rooting)<br>
开发一个 OTA（Over-The-Air）软件包，从头开始到一个Android 设备

## Pentester Lab
正确学习网络渗透测试的唯一途径就是让你的手变脏。实验教授如何手动查找与利用漏洞。您将了解问题的根源和可以用来利用它们的方法。实验基于不同系统中常见的漏洞，这些问题不是模拟的，我们为您提供的是真正的系统漏洞

- [From SQL Injection to Shell](https://pentesterlab.com/exercises/from_sqli_to_shell)<br>
实验展示了如何从 SQL 注入获得对管理控制台的访问权限，然后在管理控制台中运行命令

- [From SQL Injection to Shell II](https://pentesterlab.com/exercises/from_sqli_to_shell_II)<br>
如何从盲注 SQL 中获取对管理控制台的访问权限，然后在管理控制台中运行命令

- [From SQL Injection to Shell: PostgreSQL edition](https://pentesterlab.com/exercises/from_sqli_to_shell_pg_edition)<br>
实验展示了如何从 SQL 注入获得对管理控制台的访问权限，然后在管理控制台中运行命令

- [Web for Pentester](https://pentesterlab.com/exercises/web_for_pentester)<br>
一组最常见的 Web 漏洞

- [Web for Pentester II](https://pentesterlab.com/exercises/web_for_pentester_II)<br>
一组最常见的 Web 漏洞

- [PHP Include And Post Exploitation](https://pentesterlab.com/exercises/php_include_and_post_exploitation)<br>
本地文件包含利用的实验，还包括一些后渗透的技巧

- [Linux Host Review](https://pentesterlab.com/exercises/linux_host_review)<br>
了解如何检查 Linux 服务器的配置以确保其安全。审查的系统是常用于托管博客的传统 Linux-Apache-Mysql-PHP（LAMP） 服务器

- [Electronic Code Book](https://pentesterlab.com/exercises/ecb)<br>
如何篡改加密的 Cookies 来访问其他人的账户

- [Rack Cookies and Commands injection](https://pentesterlab.com/exercises/rack_cookies_and_commands_injection)<br>
对 Rack Cookie 的篡改，以及如何修改已签名的 Cookie（前提是不需要密码）。使用这个方法可以进行提权并获取命令执行

- [Padding Oracle](https://pentesterlab.com/exercises/padding_oracle)<br>
实验介绍了 PHP 网站认证中的一个漏洞，该网站使用密码块链接（CBC）加密用户提供的信息，并使用这些信息来确保身份验证。。我们将看到这种行为会如何影响认证以及如何被利用

- [XSS and MySQL FILE](https://pentesterlab.com/exercises/xss_and_mysql_file)<br>
介绍了如何使用跨站点脚本攻击漏洞访问管理员的 Cookie。然后，使用他/她的 Session 访问以查找 SQL 注入并执行代码执行

- [Axis2 Web service and Tomcat Manager](https://pentesterlab.com/exercises/axis2_and_tomcat_manager)<br>
实验展示了 Tomcat 和 Apache 之间的交互，以及如何调用和攻击 Axis2 Web 服务。使用从这次攻击中获取的信息，就可以访问 Tomcat 管理器并部署 WebShell 来获取命令执行

- [Play Session Injection](https://pentesterlab.com/exercises/play_session_injection)<br>
介绍了 Play 框架中会话注入的使用。这个漏洞可以绕过签名机制来篡改会话的内容

- [Play XML Entities](https://pentesterlab.com/exercises/play_xxe)<br>
实验介绍了 Play 框架中 XML 实体的利用

- [CVE-2007-1860: mod_jk double-decoding](https://pentesterlab.com/exercises/cve-2007-1860)<br>
实验介绍了 CVE-2007-1860 的使用。此漏洞允许攻击者使用制作的请求访问不可访问的页面

- [CVE-2008-1930: Wordpress 2.5 Cookie Integrity Protection Vulnerability](https://pentesterlab.com/exercises/cve-2008-1930)<br>
展示如何利用 CVE-2008-1930 访问 Wordpress 安装的管理界面

- [CVE-2012-1823: PHP CGI](https://pentesterlab.com/exercises/cve-2012-1823)<br>
如何利用 CVE-2012-1823 来检索应用程序的源代码并获取代码执行

- [CVE-2012-2661: ActiveRecord SQL injection](https://pentesterlab.com/exercises/cve-2012-2661)<br>
如何利用 CVE-2012-2661 从数据库中检索信息

- [CVE-2012-6081: MoinMoin code execution](https://pentesterlab.com/exercises/cve-2012-6081)<br>
利用 CVE-2012-6081 获取代码执行。这个漏洞可以被利用来攻陷 Debian 的 wiki 和 Python 的文档网站

- [CVE-2014-6271/Shellshock](https://pentesterlab.com/exercises/cve-2014-6271)<br>
介绍了通过 CGI 利用 Bash 漏洞的情况

## Dr. Thorsten Schneider's Binary Auditing
了解二进制审计的基本原理，了解 HLL 映射是如何工作的，获得比以往更多的内部理解。了解如何查找与分析软件漏洞，分析病毒和恶意软件的行为方式，以及如何使用一些小技巧让病毒看起来像真实程序

- [Binary Auditing](http://www.binary-auditing.com/)

## Damn Vulnerable Web Application (DVWA)
DVWA 是一个 PHP/MySQL 的 Web 应用程序，它的主要目标是帮助安全专业人士在法律环境中测试他们的技能和工具，帮助 Web 开发人员更好地理解 Web 应用程序的安全保护过程，帮助学生和教师学习受控条件下 Web 应用程序的环境

- [Damn Vulnerable Web Application (DVWA)](https://github.com/ethicalhack3r/DVWA)

## Damn Vulnerable Web Services
这是一个不安全的 Web 应用程序，具有多个易受攻击的 Web 服务组件，可用于学习真实世界的 Web 服务漏洞

- [Damn Vulnerable Web Services](https://github.com/snoopysecurity/dvws)

##  NOWASP (Mutillidae)
OWASP Mutillidae II 是一个免费、开源、存在漏洞的网络应用程序，提供了一个易于使用的网页黑客环境

- [OWASP Mutillidae](http://sourceforge.net/projects/mutillidae/files/)

##  OWASP Broken Web Applications Project
OWASP 的 Broken Web Applications Project 是一个存在漏洞 Web 应用程序集合，这些应用程序分布在 VMware 虚拟机上，与其免费和商业的 VMware 产品兼容

- [OWASP Broken Web Applications Project](https://sourceforge.net/projects/owaspbwa/files/1.2/)

## OWASP Bricks
Bricks 是一个基于 PHP 和 MySQL 构建的 Web 应用程序安全学习平台。该项目着重于常见应用程序安全问题的变化。每个“bricks”都有某种安全问题，可以手动或使用自动化软件工具来利用。使命是“打破bricks”，从而学习 Web 应用程序安全的各个方面

- [OWASP Bricks](http://sechow.com/bricks/download.html)

## OWASP Hackademic Challenges Project
在安全可控的环境中实施具有已知漏洞的现实场景。用户可以尝试发现和利用这些漏洞，以便从攻击者的角度学习信息安全的重要概念

- [OWASP Hackademic Challenges project](https://github.com/Hackademic/hackademic/)

## Web Attack and Exploitation Distro (WAED)
Web Attack and Exploitation Distro（WAED）是一个基于Debian 的轻量级虚拟机。WAED 在沙盒环境中预先配置了大约 18 个真实世界各种易受攻击的 Web 应用程序

- [Web Attack and Exploitation Distro (WAED)](http://www.waed.info/)

## Xtreme Vulnerable Web Application (XVWA)
XVWA 是一个用 PHP/MySQL 编写的糟糕的 Web 应用程序，可以帮助安全爱好者学习应用程序的安全性。因为它被设计成“非常脆弱”，所以在线使用这个应用程序是不可取的。我们建议您在本地/受控环境中托管此应用程序，并使用您自己选择的任何工具来增强您的应用程序安全性

- [Xtreme Vulnerable Web Application (XVWA)](https://github.com/s4n7h0/xvwa)

## WebGoat: A deliberately insecure Web Application
WebGoat 是由 OWASP 维护的存在漏洞的 Web 应用程序，旨在教授 Web 应用程序安全

- [WebGoat](https://github.com/WebGoat/WebGoat)

## Audi-1's SQLi-LABS
SQLi-LABS 是一个全面测试平台，可以学习和理解 SQL 注入的复杂性

- [SQLi-LABS](https://github.com/Audi-1/sqli-labs)
- [SQLi-LABS Videos](http://www.securitytube.net/user/Audi)

Capture the Flag
================

#### Hack The Box

该平台由不同难度的关卡构成，大部分内容由社区提供，在审核通过后发布。除了关卡还可以选择静态挑战或者高级任务，如 Fortress 或 Endgame

- [Hack The Box link](https://www.hackthebox.eu/)

#### Vulnhub
VulnHub 尽可能地覆盖那些存在漏洞、可破解、可利用的“东西”，希望提供学习和尝试的内容提供最佳匹配

- [Vulnhub Repository](https://www.vulnhub.com/)

#### CTF Write Ups
- [CTF Resources](https://ctfs.github.io/resources)<br>
  关于 CTF 和类似安全竞赛的信息

- [CTF write-ups 2016](https://github.com/ctfs/write-ups-2016)<br>
  由社区维护的 CTF 类似 Wiki 的 write-ups 仓库（2016 年）

- [CTF write-ups 2015](https://github.com/ctfs/write-ups-2015)<br>
  由社区维护的 CTF 类似 Wiki 的 write-ups 仓库（2015 年）

- [CTF write-ups 2014](https://github.com/ctfs/write-ups-2014)<br>
  由社区维护的 CTF 类似 Wiki 的 write-ups 仓库（2014 年）

- [CTF write-ups 2013](https://github.com/ctfs/write-ups-2013)<br>
  由社区维护的 CTF 类似 Wiki 的 write-ups 仓库（2013 年）

### CTF 仓库

- [captf](http://captf.com)<br>
  This site is primarily the work of psifertex since he needed a dump site for a variety of CTF material and since many other public sites documenting the art and sport of Hacking Capture the Flag events have come and gone over the years.

- [shell-storm](http://shell-storm.org/repo/CTF)<br>
  The Jonathan Salwan's little corner.

SecurityTube Playlists
======================

Security Tube 在 IT 安全领域提供大量视频教程，包括渗透测试，开发开发和逆向工程

* [SecurityTube Metasploit Framework Expert (SMFE)](http://www.securitytube.net/groups?operation=view&groupId=10)<br>
本视频系列涵盖了 Metasploit 框架的基础知识，如何借助 metasploit 来利用漏洞，并利用 meterpreter 进行后渗透测试技术

* [Wireless LAN Security and Penetration Testing Megaprimer](http://www.securitytube.net/groups?operation=view&groupId=9)<br>
本系列视频将带您进行无线局域网安全和渗透测试。我们将从 WLAN 的工作原理到数据包嗅探和注入攻击，甚至于审计基础设施漏洞

* [Exploit Research Megaprimer](http://www.securitytube.net/groups?operation=view&groupId=7)<br>
本系列视频中，学习如何为各种漏洞编写攻击利用代码，如何使用各种工具和技术在开源和闭源软件中找到 0 Day 漏洞

* [Buffer Overflow Exploitation Megaprimer for Linux](http://www.securitytube.net/groups?operation=view&groupId=4)<br>
本系列视频中，我们将了解缓冲区溢出的基本知识，并了解如何在基于 Linux 的系统上利用它们。在以后的视频中，我们也将看到如何将相同的原则应用到 Windows 和其他选定的操作系统

Open Security Books
===================

#### Crypto 101 - lvh
了解 SSL/TLS 等完整密码系统所需的一切：分组密码、流密码、散列函数、消息认证、公钥加密、密钥协议和签名算法。学习如何利用常见的密码缺陷、伪造管理员 Cookies、恢复密码甚至在你自己的随机数发生器里插入后门

- [Crypto101](https://www.crypto101.io/)
- [LaTeX Source](https://github.com/crypto101/book)

#### A Graduate Course in Applied Cryptography - Dan Boneh & Victor Shoup
这本书关于构建实际的系统，根据可信的假设来论证安全性。本书涵盖了密码学中不同任务的许多构造。对于每个任务我们定义所需的目标。为了分析这些结构，我们制定了一个统一的密码证明框架

- [A Graduate Course in Applied Cryptography](https://crypto.stanford.edu/~dabo/cryptobook/)

#### Security Engineering, A Guide to Building Dependable Distributed Systems - Ross Anderson
自从 2001 年这本书的第一版发布以来，世界已经发生了根本性的变化。垃圾邮件制造者，病毒作者，网络钓鱼者，洗钱者和间谍现在都忙忙碌碌，随着他们的专业化，他们变得更强。在这个全面更新的指南中，罗斯·安德森（Ross Anderson）揭示了如何建立一个可靠的系统

- [Security Engineering, Second Edition](https://www.cl.cam.ac.uk/~rja14/book.html)

#### Reverse Engineering for Beginners - Dennis Yurichev
本书提供了逆向工程的入门知识，深入研究了反汇编代码级逆向工程，并解释了如何为希望了解 x86（其中几乎涵盖了全球所有可执行软件）和 ARM 的初学者破译汇编语言由 C/C++ 编译器创建的代码

- [Reverse Engineering for Beginners](http://beginners.re/)
- [LaTeX Source](https://github.com/dennis714/RE-for-beginners)

#### CTF Field Guide - Trail of Bits
CTF 比赛倾向于衡量的重点领域是漏洞发现、漏洞创建、工具包创建等

- [CTF Field Guide](https://trailofbits.github.io/ctf/)
- [Markdown Source](https://github.com/trailofbits/ctf)

Challenges
==========

- [Reverse Engineering Challenges](https://challenges.re/)

- [Matasano Crypto Challenges](http://cryptopals.com/)

Documentation
=============

#### OWASP - Open Web Application Security Project
OWASP 是一个致力于提高软件安全性的全球非营利慈善组织，使命是提高软件安全性，以便全世界的个人和组织都能对真正的软件安全风险做出明智的决定

- [Open Web Application Security Project](https://www.owasp.org/index.php/Main_Page)

#### Applied Crypto Hardening - bettercrypto.org
本指南源于系统管理员需要有一个更新的、可靠的和深思熟虑的指南，用于配置后 Snowdenage 中的 SSL、PGP、SSH 和其他加密工具。在 2013 年夏天的 NSA 漏洞触发下，许多系统管理员和 IT 安全人员看到需要加强他们的加密设置。本指南是专门为这些系统管理员编写的

- [Applied Crypto Hardening](https://bettercrypto.org/static/applied-crypto-hardening.pdf)
- [LaTeX Source](https://github.com/BetterCrypto/Applied-Crypto-Hardening)

#### PTES - Penetration Testing Execution Standard
渗透测试执行标准涵盖渗透测试相关的所有内容 - 从渗透测试背后的初步沟通和推理，到测试人员在幕后工作的情报收集和威胁建模阶段，以便更好地理解测试组织，通过脆弱性研究，渗透测试和后渗透测试，测试人员的技术安全专业知识发挥作用，并结合企业对参与的理解，最后结合报告，捕捉整个过程，以一种有意义的方式为客户，并提供最大的价值

- [Penetration Testing Execution Standard](http://www.pentest-standard.org/index.php/Main_Page)


Related Awesome Lists
=====================

- [Awesome Pentest](https://github.com/enaqx/awesome-pentest)<br>
 收集渗透测试相关资源的仓库

- [Awesome Appsec](https://github.com/paragonie/awesome-appsec)<br>
  收集应用程序安全相关资源的仓库

- [Awesome Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)<br>
  收集恶意软件分析相关资源的仓库

- [Android Security Awesome](https://github.com/ashishb/android-security-awesome)<br>
  收集安卓安全相关资源的仓库

- [Awesome CTF](https://github.com/apsdehal/awesome-ctf)<br>
  收集 CTF 相关资源的仓库

- [Awesome Security](https://github.com/sbilly/awesome-security)<br>
  收集安全相关资源的仓库

- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots)<br>
  收集蜜罐相关资源的仓库

- [Awesome Incident Response](https://github.com/meirwah/awesome-incident-response)<br>
  收集应急响应相关资源的仓库

- [Awesome Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)<br>
  收集威胁情报相关资源的仓库

- [Awesome PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)<br>
  收集网络流量处理工具相关资源的仓库

- [Awesome Forensics](https://github.com/Cugu/awesome-forensics)<br>
  收集数字取证相关资源的仓库

- [Awesome Hacking](https://github.com/carpedm20/awesome-hacking)<br>
  收集 Hacking 相关资源的仓库

- [Awesome Industrial Control System Security](https://github.com/hslatman/awesome-industrial-control-system-security)<br>
  收集工业控制系统（ICS）相关资源的仓库

- [Awesome Web Hacking](https://github.com/infoslack/awesome-web-hacking)<br>
  收集 Web 安全相关资源的仓库

- [Awesome Sec Talks](https://github.com/PaulSec/awesome-sec-talks)<br>
  收集安全演讲相关资源的仓库

- [Awesome YARA](https://github.com/InQuest/awesome-yara)<br>
  收集 YARA 规则相关资源的仓库

- [Sec Lists](https://github.com/danielmiessler/SecLists)<br>
  安全评估期间使用的多种列表的集合，列表类型包括用户名、密码、URL、敏感数据字符串、fuzzing 的有效载荷等等

[Contributing](https://github.com/onlurking/awesome-infosec/blob/master/contributing.md)
=====================

欢迎各位提起 PR 与 issue ！

License
=======

[![Creative Commons License](http://i.creativecommons.org/l/by/4.0/88x31.png)](http://creativecommons.org/licenses/by/4.0/)

本工作使用 [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/) 许可证