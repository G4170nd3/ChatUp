# ChatUp
A basic LAN Chat application i built using python as my final year bachelors project.
Facilitiates chat messages between two users in the same private network running this applicaiton.

Working demo: demo.mp4 file included.

NOTE: The 2 recordings are not in sync so might end up looking a bit laggy, the application works in real time without any delays. (Except any delays caused by the network)

### The basic working
The application makes use of the Data Field in an ICMP packet (which **usually** contains gibberish data) to contain the payload. The ICMP packets sent out by the application are with custom Type and Code field values hence does not cause any problem to the network.
(Many firewalls may block these ICMP packets and hence render the application useless)

### What about Encryption?
I'm using Diffie-Hellman key exchange with 2048-bit prime to establish a shared symmmetric key and then the encryption is done using [Fernet encryption](https://cryptography.io/en/latest/fernet/) provided under the cryptography module in python.

### Disclaimer! (The most important part)
**This is supposed to be a small project, not to be used for actual communication. It contains multiple known vulnerabilities.**

<br/><br/>
<hr/>

Cheers!