#!/bin/sh
#
# Runs the normal multi session ZRTP receiver and a transmitter that behaves like
# a PBX (trusted MitM). This specific transmitter sends a SASRelay to the receiver
# which acts as an not enrolled receiver. The SASRelay packet thus contains the SAS
# type only, the SAS hash value is filled with zero bytes.
#
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.ReceiverMultiZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.TransmitterMultiPBX
