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

This library provides a crypto implementation that includes the
the following hash and crypto algorithms:

- SHA 256
- SHA 1
- HMAC for SHA 1 and SHA 256
- AES
- Diffie-Hellman (DH)

The crypto part of the library was copied from BouncyCastle crypto library.
Only the Diffie-Hellman part was modified to a new BigIntegerCrypto 
implementation which is also part of this package. 

BigIntegerCrypto re-uses the GNU BigInteger implementation and adds
some crypto specific enhancements:

- don't use the GMP library if installed on the system. While this
  may reduce performance it gives us full control of the data (no
  copying between Java and C)

- Add a method to clear the contents / data of the big integer. The
  application can use this function to clear data in case this big
  integer was used as a private key. Some applications may stay in 
  emory for a long time (for example communication applications) and
  thus it is important to be able to clear secret data if it is not
  longer used. Otherwise a malicious person could be able to do
  memory analysis to find some key material.
  
- Add a finalize method. If the garbage collector processes the big
  integer then the finalize method clears the data.

- Clear temporary data produced during calculations. Some big integer
  calculation produce and use temporary data. BigIntegerCrypto clears
  these temporary data to avoid data leakage. The tag "crypto:" 
  identifies these modifications.

Otherwise BigIntegerCrypto behaves in the same way as the normal
BigInteger.

The source distribution contains a short Java file that tests the 
availability of the mentioned algorithms and support classes.

Please note, this library is licensed under the GNU GPL, version 3 or 
later, and has been copyright assigned to the Free Software Foundation.

For further information refer to the ZRTP FAQ and the GNU ZRTP
How-To. Both are part of the GNU Telephony wiki and are located in its
documentation category. Here are the URLs:

http://www.gnutelephony.org/index.php/GNU_ZRTP_How_To
http://www.gnutelephony.org/index.php/ZRTP_FAQ
