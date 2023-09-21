// Only read ICMP packet's checksum
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "PacketHeader.h"

// https://jin8371.tistory.com/24
struct arp_header {
    unsigned short Hardw_type;
    unsigned short Prtoc_type;
    unsigned char Hardwadd_len;
    unsigned char Prtocadd_len;
    unsigned short Op_code;      // 패킷의 유형(req인지 rep인지 정의/req=1/rep=2)
    struct ethheader Arpsed_mac;
    struct in_addr Arpsed_ip;
    struct ethheader Arptar_mac;
    struct in_addr Arptar_ip;
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    struct ethheader * ether = (struct ethheader *)
                            (packet + sizeof(struct ethheader));
    struct tcpheader * tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader));     

    printf("     Source IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));   
    printf("Ethernet shost: %x\n", ether->ether_shost);   
    printf("Ethernet dhost: %x\n", ether->ether_dhost); 
   

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("  Protocol: TCP\n");
            printf(" TCP SPORT: %d\n", tcp->tcp_sport);    // TCP connection's starting port
            printf(" TCP DPORT: %d\n", tcp->tcp_dport);    // TCP connection's destination port
            printf("\n");
            return;
        default:      // Other protocols(ICMP, UDP, .etc)
            return;
    }
  }else if(ntohs(eth->ether_type) == 0x0806){
    struct arp_header * arp = (struct arp_header *)
                           (packet + sizeof(struct ethheader));
    printf("%02x ", arp->Arpsed_mac);
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "arp";   // tcp, udp whatever I need
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name found in ifconfig
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}