bulksslscan
===========

This script check basic SSL/TLS security configuration using sslscan under the hood.
It checks for the following basic security configuration on the server:
* __Certificate__:
 * Common Name (CN): Matches with visited address
 * Public Key Length: Recomended length is 2048 or more
 * Certificate is expired: Check non valid after and non valid before fields
 * Certificate is Autosigned: If it is autosigned is not very trustable
* __Ciphers__:
 * Minimum Key Lenght accepted by the server (>= 128 bits)
 * SSLv2 accepted
 * MAC signed with MD5
 * CBC ciphers with SSLv3 or TLSv1
 * Accept TLSv1.1 and TLSv1.2

**Usage**

./bulksslscan < ip_list_file > [< output_file.csv >]

**Results**

The script shows a colored output for each inspected IP and configuration checked.
- Green is good...
- Red is bad...

The script also output a summary on a CSV file.
