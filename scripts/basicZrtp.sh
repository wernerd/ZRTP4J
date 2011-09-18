#!/bin/sh
#
# Runs the basic ZRTP receiver and transmitter applications to check basis
# functionality
#
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.ReceiverZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/lcrypto-jdk16-143.jar:../classes" demo.TransmitterZRTP
