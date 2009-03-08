This package provides a library that adds ZRTP support to JMF
and FMJ. Phil Zimmermann developed ZRTP to allow ad-hoc, easy to
use key negotiation to setup Secure RTP (SRTP) sessions. GNU ZRTP4J
together with Sun's JMF or the free alternative FMJ provides a ZRTP
implementation that can be directly embedded into client and server
applications.

The GNU ZRTP4J implementation is compliant to the required functions of
ZRTP as described in ''draft-zimmermann-avt-zrtp-15''. Currently GNU
does not support the feature PBX SAS relay. The GNU ZRTP4J implementation 
already defines the necessary external interfaces and functions for this
feature but they are not yet implemented (stubs only).

You may access the ZRTP specification at this URL:
[http://tools.ietf.org/html/draft-zimmermann-avt-zrtp-10]

The first application that included this libarary was a SIP Communicator
release produced by Emanuel Onica during Google Summer of Code (GSoC) 2008.

This library requires a crypto implementation that includes the
the following hash and crypto algorithms:

- SHA 256
- HMAC SHA 256
- AES 128 (and optional AES 256)
- Diffie-Helman (DH)

Currently the code relies on the BouncyCastle crypto library, it does
not use JCE because this would required additional installations of
some policy files (JCE crypto policy files).

The source distribution contains a short Java file that tests the 
availability of the mentioned algorithms and support classes.

Please note, this library is licensed under the GNU GPL, version 3 or 
later, and has been copyright assigned to the Free Software Foundation.

For further information refer to the ZRTP FAQ and the GNU ZRTP
How-To. Both are part of the GNU Telephony wiki and are located in its
documentation category. Here are the URLs:

http://www.gnutelephony.org/index.php/GNU_ZRTP_How_To
http://www.gnutelephony.org/index.php/ZRTP_FAQ
