#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h> //hostent
#include <time.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "packet.h"
#include "packet_util.h"
#include "printp.h"
#include "des.h"


pcap_t *handle_sniffed = NULL;
u_char packetOut[PACKET_BUF_SIZE];
u_char packetOut_e[PACKET_BUF_SIZE];
struct timespec start, stop;
DH * dhparam;
int pk_send_size;
int pk_rcv_size;
unsigned char pk_send[1024];
unsigned char pk_rcv[1024];
unsigned char* sym_key;

double duration;

void send_pubkey(pcap_t* handle, int packetsize) {
    //printf("Packet size %d, payload size %d \n", packetsize, pk_send_size);
    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	int pktlen = generate_key_packet(packetOut, pk_send, pk_send_size, packetsize, 1, 2);
	//print_ke_packet(stdout, packetOut, pktlen);

	int ret = 0;
	if ((ret = pcap_inject(handle, packetOut, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "PUBLIC KEY SENT\n");

	//sleep(1);
}
void receive_pubkey(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;

	//print_data(stdout, (u_char*)packet, size);
	struct rthdr *rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
    u_char *packetIn = (u_char *) packet;
	int hdrlen;
    if(rth->saddr == 0x0011)
        return;

    int protocol = rth->protocol;
    if(protocol == KEY_EXCHANGE){
        //printf("Received Key\n");
        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct kehdr);
        struct kehdr* keh = (struct kehdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
        pk_rcv_size =keh->size;
        printf("Received Public Key of size %d\n", pk_rcv_size);
        printf("\n");
        bzero(pk_rcv, 1024);
        memcpy(pk_rcv, packetIn + hdrlen, pk_rcv_size);
        //printKey(pk_rcv, pk_rcv_size);

        struct BIGNUM* r_pub_key = BN_new();
        r_pub_key = BN_bin2bn(pk_rcv , pk_rcv_size, NULL);
        //printf("Use size %d \n", 4 * DH_size(dhparam));
        sym_key = (unsigned char* )malloc(DH_size(dhparam));
        //printf("Allocated size %d ", sizeof(sym_key));

        DH_compute_key(sym_key, (const struct BIGNUM*)r_pub_key, dhparam);
        printf("SYMMETRIC KEY \n");
        printKey(sym_key, sizeof(sym_key));
    }
}
void send_test_packet(pcap_t* handle, int testno, int packetsize, int source, int dest) {
	printf("==========> Test %d: generating packets of %d bytes...\n", testno, packetsize);
	int pktlen = generate_openflow_test_packet(packetOut, packetsize, testno, source, dest);
	print_rl_packet(stdout, packetOut, pktlen);
	encrypt((const u_char *)packetOut, packetOut_e, pktlen);
	int ret = 0;
	//print_data(stdout, packetOut, pktlen);
	/*printf("generating packets of 8 bytes...\n");
	generate_random_packet(packetOut, 8);*/

	if ((ret = pcap_inject(handle, packetOut_e, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "DONE\n");
	usleep(50);
	//sleep(1);
}


void receive_ack(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;
	if (verify_packet_chk((u_char*)packet, size, ROUTE_ON_RELIABLE) == 0) {
		if( clock_gettime( CLOCK_REALTIME, &stop) == -1 ) { perror( "clock gettime" );}
		duration = (stop.tv_sec - start.tv_sec)+ (double)(stop.tv_nsec - start.tv_nsec)/1e9;
		fprintf(stdout, "Execution time: %f sec, throughput: %fpps, %fbps\n", duration, TEST_SEQ_CNT/duration, TEST_SEQ_CNT*256*8/duration);
		exit(1);
	}
}

void keyExchange(){
    dhparam = DH_new();
    if(dhparam == NULL){
        printf("Unable to allocate DH \n");
    }

    FILE * f = fopen("dh1024.pem" , "r");
    if (f == NULL)
        printf("Cannot Open file to read \n");

    dhparam = PEM_read_DHparams(f, NULL, NULL, NULL);
	//Generate Public and Private Keys

	DH_generate_key(dhparam);
    //Send my public key
    bzero(pk_send, 1024);
    pk_send_size = BN_num_bytes(dhparam->pub_key);
    BN_bn2bin(dhparam->pub_key, pk_send);
    //printf("Send Size %d \n", pk_send_size);
    //printKey(pk_send, pk_send_size);
    char c[20];
    fprintf(stdout, "Please enter Y/y to send my public key \n");
    scanf("%s", &c);
    send_pubkey(handle_sniffed, 256);


    // TODO: receive Public key of node at other end
    pcap_loop(handle_sniffed, 5, receive_pubkey , NULL);

}

int main (int argc, char** argv) {
	if (argc < 3) {
		printf("Usage: sudo ./sender source destination\n");
		exit(1);
	}
	int source = atoi(argv[1]);
	int dest = atoi(argv[2]);
	pcap_if_t *device_list = NULL;		// Linked list of all devices discovered
	pcap_if_t *device_ptr = NULL;		// Pointer to a single device


	char err[128];						// Holds the error
	char *device_name = NULL;
	char devices[10][64];				// For holding all available
	int count = 0;
	int ret = 0;
	int n = 0;

	srand(time(NULL));

	printf("Scanning available devices ... ");
	if ( (ret = pcap_findalldevs(&device_list, err)) != 0 ) {
		fprintf(stderr, "Error scanning devices, with error code %d, and error message %s\n", ret, err);
		exit(1);
	}
	printf("DONE\n");

	printf("Here are the available devices:\n");
	for (device_ptr = device_list; device_ptr != NULL; device_ptr = device_ptr->next) {
		printf("%d. %s\t-\t%s\n", count, device_ptr->name, device_ptr->description);
		if (device_ptr->name != NULL) {
			strcpy(devices[count], device_ptr->name);
		}
		count++;
	}

	printf("Which device do you want to sniff? Enter the number:\n");
	scanf("%d", &n);
	device_name = devices[n];

	printf("Trying to open device %s to send ... ", device_name);
	if ( (handle_sniffed = pcap_open_live(device_name, BUFSIZ, 1, 100, err)) == NULL ) {
		fprintf(stderr, "Error opening device %s, with error message %s\n", device_name, err);
		exit(1);
	}
	printf( "DONE\n");

    keyExchange();

//    char c[20];
//    fprintf(stdout, "Please enter Y/y to start sending packets\n");
//    scanf("%s", &c);
//
//	int i;
//	if( clock_gettime( CLOCK_REALTIME, &start) == -1 ) { perror( "clock gettime" );}
//	for (i = 0; i < TEST_SEQ_CNT; i++) {
//		send_test_packet(handle_sniffed, i, 1024, source, dest);
//	}
//	printf("Waiting for ACK...\n");
//	pcap_loop(handle_sniffed, -1, receive_ack, NULL);


	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}




