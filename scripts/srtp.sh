java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.ReceiverSRTP &
sleep 2
java -cp "../lib/jmf.jar:../lib/bcprov-jdk15on-148.jar:../lib/bccontrib-1.0-SNAPSHOT.jar:../classes" demo.TransmitterSRTP
