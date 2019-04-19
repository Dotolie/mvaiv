#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define MY_DEST_MAC0	0x2c
#define MY_DEST_MAC1	0x41
#define MY_DEST_MAC2	0x38
#define MY_DEST_MAC3	0x60
#define MY_DEST_MAC4	0xc8
#define MY_DEST_MAC5	0x04

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

//! \brief
//!     Calculate the UDP checksum (calculated with the whole
//!     packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr)
{
        const uint16_t *buf=(uint16_t *)buff;
        uint16_t *ip_src=(uint16_t *)&src_addr, *ip_dst=(uint16_t *)&dest_addr;
        uint32_t sum;
        size_t length=len;

        // Calculate the sum                                            //
        sum = 0;
        while (len > 1)
        {
                sum += *buf++;
                if (sum & 0x80000000)
                        sum = (sum & 0xFFFF) + (sum >> 16);
                len -= 2;
        }

        if ( len & 1 )
                // Add the padding if the packet lenght is odd          //
                sum += *((uint8_t *)buf);

        // Add the pseudo-header                                        //
        sum += *(ip_src++);
        sum += *ip_src;

        sum += *(ip_dst++);
        sum += *ip_dst;

        sum += htons(IPPROTO_UDP);
        sum += htons(length);

        // Add the carries                                              //
        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        // Return the one's complement of sum                           //
        return ( (uint16_t)(~sum)  );
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *piphdr, unsigned int count) 
{

	register unsigned long sum = 0;
	while (count > 1) {
	sum += * piphdr++;
	count -= 2;
	}

	//if any bytes left, pad the bytes and add
	if(count > 0) {
	sum += ((*piphdr)&htons(0xFF00));
	}


	//Fold sum to 16 bits: add carrier to result
	while (sum>>16) {
	  sum = (sum & 0xffff) + (sum >> 16);
	}


	//one's complement
	sum = ~sum;
	return ((unsigned short)sum);

}


int main(int argc, char *argv[])
{
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	char data[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct udphdr *udp = (struct udphdr *) (sendbuf + sizeof(struct iphdr) + sizeof(struct ether_header));
	
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, 0/*IPPROTO_RAW*/)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	eh->ether_type = htons(ETH_P_IP);


	tx_len += sizeof(struct ether_header)+sizeof(struct iphdr) + sizeof(struct udphdr);

	/* Packet data */
	sprintf(data, "%s", "Hello my name");
	strcpy((sendbuf+tx_len), data);
	tx_len += strlen(data);

	

	// fabricate the IP header
	iph->ihl      = 5;
	iph->version  = 4;
	iph->tos      = 0; // low delay
	iph->tot_len  = htons( sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data));
	iph->id       = htons(30664);
	iph->ttl      = 64; // hops
	iph->protocol = 17; // UDP
	// source IP address, can use spoofed address here
	iph->saddr = inet_addr("10.168.0.2");
	iph->daddr = inet_addr("192.168.0.12");

	//printf("ip=%d, udp=%d, data=%d, tot=%d\r\n",sizeof(struct iphdr), sizeof(struct udphdr), strlen(data), (sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data)));


	// fabricate the UDP header
	udp->source = htons(66669);
	// destination port number
	udp->dest = htons(2021);
	udp->len = htons(sizeof(struct udphdr)+strlen(data));
	udp->check = udp_checksum((sendbuf+ sizeof(struct ether_header)+sizeof(struct iphdr)),
										(sizeof(struct udphdr)+ strlen(data)),
										inet_addr("10.168.0.2"),
										inet_addr("192.168.0.12"));


	// calculate the checksum for integrity
	iph->check = compute_checksum((unsigned short*)iph, iph->ihl<<2);
//	printf("udp-ch=0x%x, iph-ch=0x%x\r\n", htons(udp->check), htons(iph->check));
	
	

	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}
