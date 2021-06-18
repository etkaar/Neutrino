# Neutrino
Secure and event-driven low-level UDP protocol with focus on simplicity and high performance.

The basic Neutrino class (*Neutrino Simple* or only *Neutrino*) does only offer an event-driven and encrypted server/client scheme using small packets of not more than 1280 bytes. While TCP emulates a stream-based protocol, UDP and thus Neutrino uses a packet-based scheme.

Features such as acknowledgement packets (ACK), ordering packets by their given packet number or allowing large pseudo-packets to bypass the limit are out of scope for the basic class; but are planned to be developed as extended classes.

# When to use Neutrino?

You may use Neutrino (Simple) if you already decided you want to work with UDP, but need strict encryption.

# Public-Key Authentication
The packet payload and a part of the header (containing the packet number) is encrypted using [XChaCha20-Poly1305](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction). This functionality is provided by the easily portable libsodium project which is available in PHP and in Python via PyNaCl.

# Code Styling
  - Type hints for class variables, but none for function variables.
  - Type hints for function arguments and return values.
	  
# Requirements / Dependencies
  - Python >= 3.7
  - PyNaCl (libsodium / https://github.com/jedisct1/libsodium)
