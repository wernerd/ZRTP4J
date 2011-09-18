#!/bin/sh
#
# Runs the multi session ZRTP receiver and transmitter applications to check the
# multisession functionality
#
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.ReceiverMultiZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.TransmitterMultiZRTP
