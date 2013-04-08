#!/bin/sh
#
# Runs the multi session ZRTP receiver and transmitter applications to check the
# multisession functionality
#
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.ReceiverMultiZRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.TransmitterMultiZRTP
