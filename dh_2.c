#include <pcap.h>
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <unistd.h>
#include <time.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <netinet/in.h>
#include <netdb.h> //hostent
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

#include "packet_util.h"
#include "printp.h"
#include "des.h"

int checkArray[TEST_SEQ_CNT];
u_char packetOut[PACKET_BUF_SIZE];

int source, dest;
pcap_t *handle_sniffed = NULL;
DH * dhparam;
int pk_send_size;
int pk_rcv_size;
unsigned char pk_send[1024];
unsigned char pk_rcv[1024];
unsigned char* sym_key;

void send_pubkey(pcap_t* handle, int packetsize) {
    //printf("Packet size %d, payload size %d \n", packetsize, pk_send_size);
    memset(packetOut, 0, sizeof(u_char) * PACKET_BUF_SIZE);
	int pktlen = generate_key_packet(packetOut, pk_send, pk_send_size, packetsize, 2, 1);
	//print_ke_packet(stdout, packetOut, pktlen);

	int ret = 0;
	if ((ret = pcap_inject(handle, packetOut, pktlen)) < 0){
		fprintf(stderr, "Fail to inject packet\n");
		// exit(1);
	}
	printf( "PUBLIC KEY SENT\n\n");

	//sleep(1);
}
void receive_pubkey(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = (int) header->len;

	//print_data(stdout, (u_char*)packet, size);
	struct rthdr *rth = (struct rthdr*) (packet + sizeof(struct ethhdr));
    u_char *packetIn = (u_char *) packet;
	int hdrlen;
    if(rth->saddr == 0x0021)
        return;

    int protocol = rth->protocol;
    if(protocol == KEY_EXCHANGE){
        //printf("Received Key Packet of size %d\n", size);
        hdrlen = sizeof(struct ethhdr) + sizeof(struct rthdr) + sizeof(struct kehdr);
        struct kehdr* keh = (struct kehdr*)(packetIn + sizeof(struct ethhdr) + sizeof(struct rthdr));
        pk_rcv_size = keh->size;
        bzero(pk_rcv, 1024);
        memcpy(pk_rcv, packetIn + hdrlen, pk_rcv_size);
        printf("Received Public Key of size %d\n", pk_rcv_size);
        printf("\n");
        //printKey(pk_rcv, pk_rcv_size);

        char c[20];
        fprintf(stdout, "Please enter Y/y to send my public key \n");
        scanf("%s", &c);
        send_pubkey(handle_sniffed, 256);

        struct BIGNUM* r_pub_key = BN_new();

    // TODO: receive Public key of node at other end

        r_pub_key = BN_bin2bn(pk_rcv , pk_rcv_size, NULL);
        sym_key = (unsigned char* )malloc(DH_size(dhparam));

        DH_compute_key(sym_key, (const struct BIGNUM*)r_pub_key, dhparam);
        printf("SYMMETRIC KEY \n");
        printKey(sym_key, sizeof(sym_key));
    }
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	int size = (int) header->len;
	int seq = -1;
	int i;
	int ret;
	u_char packet_d[PACKET_BUF_SIZE];

	decrypt(packet, packet_d, size);
	print_rl_packet(stdout, packet_d, size);
	if (verify_packet_chk((u_char*)packet_d, size, ROUTE_ON_RELIABLE) == 0) {
		struct rlhdr* rlh = (struct rlhdr*)(packet_d + ETH_HLEN + sizeof(struct rthdr));
		seq = ntohs(rlh->seq);
		fprintf(stdout, "Received sequence %d\n", seq);
		checkArray[seq] = 1;
		for (i = 0; i < TEST_SEQ_CNT; i++) {
			if (checkArray[i] != 1) {
				return;
			}
		}
		printf("ALL test segments received.\n");
		int pktlen = generate_openflow_test_packet(packetOut, 128, 9999, source, dest);
		if ((ret = pcap_inject(handle_sniffed, packetOut, pktlen)) < 0){
			fprintf(stderr, "Fail to inject packet\n");
			// exit(1);
		}
		exit(1);
	}
	else{
        printf("Packet checksum failed \n");
	}
	//print_data(stdout, (u_char*)packet, size);
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
    //printKey(pub_key_buffer, BN_num_bytes(dhparam->pub_key));
    pcap_loop(handle_sniffed, 5, receive_pubkey , NULL);
}


int main (int argc, char** argv) {
	if (argc != 3) {
		printf("Usage: sudo ./pcap_receiver source destination\n");
		exit(1);
	}
	source = atoi(argv[1]);
	dest = atoi(argv[2]);
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
	//pcap_loop(handle_sniffed , -1 , process_packet , NULL);	// -1 means an infinite loop

	printf( "END OF TEST\n");
	pcap_close(handle_sniffed);

	return 0;
}




