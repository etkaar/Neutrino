# Neutrino
Neutrino is an encrypted and event-driven UDP based network protocol. Due to its event-driven design, it does **not** make use of `asyncio`.

Most of the development has taken place between 2021 and 2022. In July 2024 I started to use Neutrino in production. It is the direct result of a personal research project, which goals and thoughts were as follows:

- **UDP vs TCP**: TCP nowadays is too complex and intransparent since it shall serve as a all-in-one solution (so-called [protocol ossification](https://en.wikipedia.org/wiki/Protocol_ossification)). UDP can be way more effective for a new network protocol which is the reason that HTTP/3 ([QUIC](https://en.wikipedia.org/wiki/QUIC)) is using it.
- **Events vs Asyncio**: Given the stateless design of UDP, I decided that even-though Neutrino brings statefulness it is more natural to use a pure event-driven design without making use of `asyncio`. Another reason for this was that I think it ensures simpler portability.
- **Separation**: Designing a network protocol is not an easy task, but the basic Neutrino protocol ([Neutrino.py](https://github.com/etkaar/Neutrino/blob/main/source/Python/Neutrino.py)) consists of less than 2,000 lines including all the comments. It makes it easy for interested people to learn how it works and to modify it. This only works if it is not an all-in-one solution. The reliable version of Neutrino ([NeutrinoReliable.py](https://github.com/etkaar/Neutrino/blob/main/source/Python/NeutrinoReliable.py)) (which detects loss, ensures that packets are in order and not duplicated) contains less than 600 lines of code including comments and extends Neutrino by these features.

As said, for better separation of concerns it comes in three different versions – the basic version and two extensions:

- **Neutrino**<br>
  The basic protocol. Packets<sup>1</sup> are always encrypted and must have a size of <= 1280 bytes.
  
- **NeutrinoReliable**<br>
  An extension which introduces detection and correction of packet loss and detection of duplicates or packets which are out of order.
  
- *NeutrinoReliableExtended* <sup>(Not ready yet)</sup><br>
  Relies on NeutrinoReliable and raises the packet size limit.

<small><sup>1</sup> With the exception of the initial *PACKET_TYPE_CLIENT_HELLO1*.</small><br>

### Examples

For a short example use `ServerExampleNeutrinoReliable.py` and `ClientExampleNeutrinoReliable.py`, see [here](https://github.com/etkaar/Neutrino/tree/main/source/Python/examples).

### Inspector

The Inspector is used for testing purposes. For instance, it interferes with the traffic to trigger the duplicate packet or packet loss detection.

### Monitoring

The Monitoring class is also used for testing purposes. It more or less visualizes the traffic:

#### Server

![image](https://github.com/user-attachments/assets/216be854-a0c1-4471-9bd3-fa6ee17d563b)

#### Client

![image](https://github.com/user-attachments/assets/804e3abd-1856-423b-8be9-14f3bfd76476)

### Requirements
- Python >= 3.7
  - PyNaCl (libsodium / https://github.com/jedisct1/libsodium)

---

## Description

## 1.0 Public-Key Authentication
The packet payload and parts of the header (containing the packet number) are encrypted using [XChaCha20-Poly1305](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). This functionality is provided by the easily portable [libsodium](https://github.com/jedisct1/libsodium) project which is available in Python via PyNaCl.

```shell
apt install python3-nacl
```

---

## 2.0 Packet Format

```lua
RAW_PACKET = (HEADER + PAYLOAD)
```

### 2.1 Header

The header consists of a left and right part. While the left part is unprotected (not encrypted), the right side – which includes the packet number – is protected (encrypted).

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

#### 2.2.1 Neutrino and NeutrinoReliable

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

#### 2.2.1 NeutrinoReliableExtended

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
