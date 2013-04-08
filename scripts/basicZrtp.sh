#!/bin/sh
#
# Runs the basic ZRTP receiver and transmitter applications to check basis
# functionality
#
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.ReceiverZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.TransmitterZRTP
