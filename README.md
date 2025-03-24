
# W1seGuy Challenge Writeup - TryHackMe

![TryHackMe Logo](https://tryhackme.com/img/THMlogo.png)

**Author**: Housma  
**Date**: 24-03-2025  
**Challenge**: W1seGuy  
**Platform**: TryHackMe  
**Difficulty**: Easy  
**Category**: Cryptography  
**Tags**: `XOR` `Known-Plaintext Attack` `pwntools`

**W1seGuy Room** on TryHackMe:  
[https://tryhackme.com/room/w1seguy](https://tryhackme.com/room/w1seguy)

## Table of Contents
- [Challenge Overview](#challenge-overview)
- [Source Code Analysis](#source-code-analysis)
- [Solution Approach](#solution-approach)
- [Exploit Code](#exploit-code)
- [Results](#results)
- [Key Takeaways](#key-takeaways)
- [Prevention](#prevention)

## Challenge Overview

This challenge involves breaking a simple XOR encryption scheme to recover two flags:
1. **Flag 1**: Hidden in an XOR-encoded message
2. **Flag 2**: Received after submitting the correct encryption key

The server provides an XOR-encoded message containing Flag 1 and requires us to derive the encryption key to obtain Flag 2.

## Source Code Analysis

The server's source code reveals critical information:

```python
def setup(server, key):
    flag = 'THM{thisisafakeflag}'  # Known plaintext
    xored = ""
    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))
    return xored.encode().hex()

def start(server):
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    hex_encoded = setup(server, key)
    send_message(server, f"This XOR encoded text has flag 1: {hex_encoded}\n")
```

### Key observations:
- Uses repeating-key XOR with 5-character alphanumeric key
- Encrypts a known plaintext structure (`THM{...}`)
- Provides Flag 2 after correct key submission

## Solution Approach

### Vulnerability Analysis

The encryption is vulnerable due to:
- Known plaintext structure (THM{ prefix and } suffix)
- Short key length (5 characters)
- Repeating key pattern

### Attack Strategy
1. Capture the ciphertext from server.
2. Derive the key using a known plaintext attack:
   - First 4 bytes: XOR ciphertext with `THM{`
   - Last byte: XOR final cipher byte with `}`
3. Decrypt Flag 1 using the recovered key.
4. Submit the key to get Flag 2.

## Exploit Code

```python
from pwn import *

def solve():
    # Connect to target server
    conn = remote('10.10.132.107', 1337)
    
    # Extract ciphertext
    conn.recvuntil(b"flag 1: ")
    hex_data = conn.recvline().strip().decode()
    cipher = bytes.fromhex(hex_data)
    
    # Recover 5-byte key
    key_part1 = bytes([cipher[i] ^ ord('THM{'[i]) for i in range(4)])
    key_part2 = cipher[-1] ^ ord('}')
    key = key_part1 + bytes([key_part2])
    
    # Decrypt Flag 1
    flag1 = bytes([cipher[i] ^ key[i%5] for i in range(len(cipher))]).decode()
    
    # Get Flag 2
    conn.sendline(key)
    flag2 = conn.recvuntil(b'}').decode()
    
    print(f"[+] Flag 1: {flag1}")
    print(f"[+] Flag 2: {flag2}")
    conn.close()

if __name__ == "__main__":
    solve()
```

## Results
![Screenshot of terminal](https://raw.githubusercontent.com/Housma/TryHackMe-W1seGuy-Writeup/refs/heads/main/run.JPG)

- **Flag 1**: Retrieved from the decrypted ciphertext.
- **Flag 2**: Received by submitting the correct key to the server.

## Key Takeaways

### Cryptographic Weaknesses:
- XOR encryption is vulnerable to known-plaintext attacks.
- Short keys are susceptible to brute-force attacks.
- Repeating key patterns weaken security.

### Attack Techniques:
- Leveraged known plaintext structure.
- Recovered key through partial plaintext knowledge.
- Demonstrated practical ciphertext-only attack.

### Best Practices:
- Never implement custom crypto algorithms.
- Use established libraries (AES, RSA, etc.).
- Always use sufficiently long keys.

## Prevention
For secure communication:
- Use AES-256 instead of XOR.
- Implement proper key management.
- Add HMAC for message authentication.
- Consider TLS for network communication.


*"In cryptography, what looks secure today may be broken tomorrow."*

Housma
