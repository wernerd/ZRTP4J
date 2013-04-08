#!/bin/sh
#
# Runs the normal multi session ZRTP receiver and a transmitter that behaves like
# a PBX (trusted MitM). This specific transmitter sends a SASRelay to the receiver
# which acts as an not enrolled receiver. The SASRelay packet thus contains the SAS
# type only, the SAS hash value is filled with zero bytes.
#
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.ReceiverMultiZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.TransmitterMultiPBX
