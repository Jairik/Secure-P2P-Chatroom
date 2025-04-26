# 📚 Open-Access Papers on Modern Encryption and Secure Messaging (2015–2025)

---

# Open-Source References for Secure P2P Chat Stack  

> **Topics covered:**  
> *ChaCha20-Poly1305 authenticated encryption – Ed25519 message signatures – UDP broadcast for P2P peer discovery / NAT traversal*  

---

## 1  ChaCha20-Poly1305 (AEAD)

| Ref | Title & Link | One-Sentence Summary |
|-----|--------------|-----------------------|
| **C1** | **RFC 8439 – _ChaCha20 and Poly1305 for IETF Protocols_** (2018) <br> <https://www.rfc-editor.org/rfc/rfc8439.pdf> | The official IETF/IRTF spec: defines the ChaCha20 cipher, Poly1305 MAC and their AEAD construction, gives test vectors and implementation guidance (supported in OpenSSL and the Python `cryptography` API). |
| **C2** | **Procter – _A Security Analysis of the Composition of ChaCha20 and Poly1305_** (IACR ePrint 2014/613) <br> <https://eprint.iacr.org/2014/613.pdf> | Provides the first formal single-user security proof for ChaCha20-Poly1305, showing tight bounds and highlighting why the straightforward “encrypt-then-MAC” composition is robust. |
| **C3** | **Degabriele et al. – _The Security of ChaCha20-Poly1305 in the Multi-User Setting_** (IACR ePrint 2023/085) <br> <https://eprint.iacr.org/2023/085.pdf> | Extends the analysis to many-user environments (e.g., the Internet), derives concrete re-keying limits for TLS 1.3/QUIC, and compares the scheme’s security/performance trade-offs with AES-GCM. |

---

## 2  Ed25519 (Signatures & Identity)

| Ref | Title & Link | One-Sentence Summary |
|-----|--------------|-----------------------|
| **E1** | **Bernstein et al. – _High-Speed High-Security Signatures (Ed25519)_** (2011) <br> <https://ed25519.cr.yp.to/ed25519-20110926.pdf> | Introduces Ed25519, benchmarks 100 k signatures /s on a quad-core Xeon, and releases constant-time reference code to the public domain. |
| **E2** | **RFC 8032 – _Edwards-Curve Digital Signature Algorithm (EdDSA)_** (2017) <br> <https://www.rfc-editor.org/rfc/rfc8032.pdf> | Standardizes Ed25519/Ed448, supplies deterministic signing/verification algorithms, encoding rules, and test vectors adopted by OpenSSH, libsodium and the Python `cryptography` library. |
| **E3** | **Owens et al. – _Efficient and Side-Channel-Resistant Ed25519 on ARM Cortex-M4_** (2023) <br> <https://par.nsf.gov/servlets/purl/10507285> | Presents an assembly-optimized, TVLA-tested implementation for IoT MCUs: 200 k cycles key-gen, 240 k cycles sign, 720 k cycles verify – useful if you target embedded hardware. |

---

## 3  UDP Broadcast / NAT Traversal for P2P

| Ref | Title & Link | One-Sentence Summary |
|-----|--------------|-----------------------|
| **U1** | **BEP-14 – _BitTorrent Local Service Discovery (UDP Multicast)_** (2015) <br> <https://www.bittorrent.org/beps/bep_0014.html> | Specifies the HTTP-over-UDP multicast messages (`BT-SEARCH`) that let BitTorrent clients auto-discover peers on the same LAN without any tracker. |
| **U2** | **Ford-Srisuresh-Kegel – _Peer-to-Peer Communication Across Network Address Translators_** (2005) <br> <https://pdos.csail.mit.edu/papers/p2pnat.pdf> | Classic paper that formalises UDP (and TCP) “hole punching,” measures support across real NAT devices, and explains why the method is safe yet widely compatible. |
| **U3** | **Chowdhury – _NAT Traversal Techniques: A Survey_** (IJCA Vol 175 No 32, 2020) <br> <https://www.ijcaonline.org/archives/volume175/number32/chowdhury-2020-ijca-920885.pdf> | Surveys STUN, TURN, UDP hole punching and more, comparing strengths/weaknesses and offering decision tables for P2P designers. |

---

### How this helps your project  

* **ChaCha20-Poly1305 & Ed25519** are available directly in the Python `cryptography` package (`from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305`, `from cryptography.hazmat.primitives.asymmetric import ed25519`) so you can prototype quickly without rolling your own crypto.  
* **BEP-14 + hole-punching** give you a proven recipe for LAN discovery _and_ global connectivity. Pair U1’s multicast discovery with U2’s UDP hole punching and fallback to a TURN-style relay if both peers sit behind strict symmetric NATs (cf. U3’s comparison tables).  

Feel free to drop any of these straight into your literature review or implementation notes!


[More In Depth Summary](https://chatgpt.com/s/dr_680ce2e042d88191b3222f2274a4a70e)
