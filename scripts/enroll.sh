#!/bin/sh
#
# Runs the normal multi session ZRTP receiver and a transmitter that behaves like
# a PBX (trusted MitM). This specific transmitter behaves like a PBX enrollment service.
# It computes the PBX secret and stores it for the partner ZID record and also sets
# the enrollment flags in the confirm packets.
#
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.ReceiverMultiPBXEnroll &
sleep 2
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.TransmitterMultiPBXEnroll
