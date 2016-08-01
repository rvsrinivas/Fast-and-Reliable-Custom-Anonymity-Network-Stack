pcap_sender: pcap_sender.o printp.o packet_util.o des.o
	gcc -g -Wall -o pcap_sender pcap_sender.o printp.o packet_util.o des.o -lpcap -lrt -lcrypto
pcap_receiver: pcap_receiver.o printp.o packet_util.o des.o
	gcc -g -Wall -o pcap_receiver pcap_receiver.o printp.o packet_util.o des.o -lpcap -lrt -lcrypto
	
dh_2: dh_2.o printp.o packet_util.o des.o
	gcc -o dh_2 -g dh_2.o printp.o packet_util.o des.o -lcrypto -lpcap -lrt
dh_2.o: dh_2.c
	gcc -g -c -Wall dh_2.c
dh_1: dh_1.o printp.o packet_util.o des.o
	gcc -o dh_1 -g dh_1.o printp.o packet_util.o des.o -lcrypto -lpcap -lrt
dh_1.o: dh_1.c
	gcc -g -c -Wall dh_1.c
des: des.o 
	gcc -o des -g des.o -lcrypto
des.o: des.c
	gcc -g -c -Wall des.c
	
router: router.o routing.o printp.o packet_util.o
	gcc -g -Wall -o router router.o routing.o printp.o packet_util.o -lpthread -lpcap
routing: routing.o
	gcc -g -Wall -o routing routing.o
router.o: router.c packet.h printp.h routing.h packet_util.h
	gcc -g -c -Wall router.c
routing.o: routing.c routing.h packet.h
	gcc -g -c -Wall routing.c
printp.o: printp.c packet.h printp.h packet_util.h
	gcc -g -c -Wall printp.c
packet_util.o: packet_util.c packet.h packet_util.h printp.h
	gcc -g -c -Wall packet_util.c
packet_test.o: packet_test.c packet.h packet_util.h printp.h routing.h
	gcc -g -c -Wall packet_test.c
pcap_sender.o: pcap_sender.c packet.h packet_util.h printp.h des.h
	gcc -g -c -Wall pcap_sender.c
pcap_receiver.o: pcap_receiver.c packet_util.h printp.h des.h
	gcc -g -c -Wall pcap_receiver.c

clean:
	rm -f *.o des-basic pcap_sender pcap_receiver router routing dh_1 dh_2