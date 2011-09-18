#!/bin/sh
#
# Runs the normal multi session ZRTP receiver and a transmitter that behaves like
# a PBX (trusted MitM). This transmitter acts as a PBX and sends a SASrelay to
# an enrolled receiver. Instead of using the other party's sas hash value the transmitter
# constructs a sas hash value to enable an easy check if it work out.
#
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.ReceiverMultiPBXEnroll &
sleep 2
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.TransmitterMultiPBXEnrolled
