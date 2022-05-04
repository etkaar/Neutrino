**👷‍♀️ Neutrino is currently under development and not to be used in production yet. 👷**

# Neutrino
Neutrino is an encrypted and event-driven UDP based network protocol with focus on simplicity (as far this is possible which such a protocol) and high performance.

The idea for Neutrino initially came from [QUIC](https://en.wikipedia.org/wiki/QUIC) which is expected to replace TCP with encrypted UDP in HTTP/3. Due to the lack of implementations and the complexity of this protocol (and the lack of encryption in UDP) I decided to create a module based Neutrino, where in the basic version at least encrypted UDP can be provided, which is mandatory nowadays.

For better separation of concerns it comes in three different versions – the basic version and two extensions:

- **Neutrino**<br>
  The basic protocol. Packets<sup>1</sup> are always encrypted and must have a size of <= 1280 bytes.
  
- **NeutrinoReliable**<br>
  An extension which introduces detection and correction of packet loss and detection of duplicates or packets which are out of order.
  
- **NeutrinoExtended**<br>
  Relies on NeutrinoReliable and raises the packet size limit.

<small><sup>1</sup> With the exception of the initial *PACKET_TYPE_CLIENT_HELLO1*.</small>

## Requirements
- Python >= 3.7
  - PyNaCl (libsodium / https://github.com/jedisct1/libsodium)

---

## 1.0 Public-Key Authentication
The packet payload and parts of the header (containing the packet number) are encrypted using [XChaCha20-Poly1305](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). This functionality is provided by the easily portable libsodium project which is available in PHP and in Python via PyNaCl.

---

## 2.0 Packet Format

```lua
RAW_PACKET = (HEADER + PAYLOAD)
```

### 2.1 Header

The header consists of a left and right part. While the left part is unprotected, the right side – which includes the packet number – is protected.

```lua
HEADER(
   UNPROTECTED(
      [Protocol Identifier = u32 bit (4 bytes)]
      [Protocol Version = u8 bit (1 byte)]
      [Type = u8 bit (1)]
      [Session ID = u64 bit (8 bytes)]
   )

   ENCRYPTED(
      [Packet Number = u64 bit (8 bytes)]
      [Keyword: Reserved for arbitrary use = u32 bit (4)]
   )
)
```

### 2.2 Payload

#### 2.2.1 Neutrino + NeutrinoReliable

```lua
PAYLOAD(
   [Amount of Payload Words = u8 bit (1 byte)]
   for word_number_n=0 to [Amount of Payload Words]
   WORD_N(
      [Playload Word Size = u16 bit (2 bytes)]
      [Word = ? bytes]
   )
)
```

#### 2.2.1 NeutrinoExtended

```lua
PAYLOAD(
   [Amount of Payload Words = u16 bit (2 bytes)]
   for word_number_n=0 to [Amount of Payload Words]
   WORD_N(
      [Playload Word Size = u32 bit (4 bytes)]
      [Word = ? bytes]
   )
)
```

---

## 3.0 Code Styling
- Python
  - Type hints for class variables, but none for function variables.
  - Type hints for function arguments and return values.

