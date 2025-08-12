# Secure Encrypted Chat System  
*A Python-based secure communication platform demonstrating real-world cryptography implementation*  

![Demo GIF](./assets/demo.gif) *(Replace with actual demo video)*  

---

## 📌 Objective  
To build a **secure, multi-client chat application** that:  
- Implements **end-to-end encryption** using industry-standard protocols  
- Demonstrates **secure authentication** without plaintext credential exposure  
- Provides **perfect forward secrecy** through session-based key generation  
- Serves as a **portfolio piece** showcasing cybersecurity and networking skills  

---

## Tools & Technologies Used  

| Category          | Technologies |  
|-------------------|--------------|  
| **Cryptography**  | AES-256-GCM, Diffie-Hellman (2048-bit), HKDF-SHA256 |  
| **Networking**    | Python `socket`, `threading` |  
| **Authentication**| Encrypted credential exchange |  
| **Development**   | Python 3.9+, Wireshark (for packet analysis) |  

---

## Skills Demonstrated  

### Core Cybersecurity  
- Implemented **Diffie-Hellman key exchange** to prevent MITM attacks  
- Designed **AES-GCM encryption** for message confidentiality & integrity  
- Secured authentication with **encrypted credential transmission**  

### Software Engineering  
- Built a **multi-threaded TCP server** handling concurrent clients  
- Engineered **protocol framing** (length-prefixed messages)  
- Structured code for **modularity** and **maintainability**  

### Debugging & Validation  
- Verified encryption with **Wireshark packet analysis**  
- Implemented **debug logs** for key derivation and message flow  
- Stress-tested with **multiple concurrent clients**  

---

## Key Features  
| Feature | Implementation | Security Benefit |  
|---------|---------------|------------------|  
| **Session-Based Keys** | New DH exchange per connection | Perfect forward secrecy |  
| **Encrypted Auth** | Username/password via AES-GCM | Prevents credential sniffing |  
| **Message Integrity** | AES-GCM authentication tags | Detects tampering |  
| **Threaded Server** | Handles 50+ concurrent clients | Scalable architecture |  

---

## Setup & Usage  

### Prerequisites  
- Python 3.9+  
- cryptography package  

```bash
# Clone repository
git clone https://github.com/yourusername/secure-chat.git
cd secure-chat

# Install dependencies
pip install cryptography

# Start server (in one terminal)
python server.py

# Run clients (in separate terminals)
python client.py
