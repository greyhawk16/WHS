#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    struct ethheader * ether = (struct ethheader *)
                            (packet + sizeof(struct ethheader));
    struct icmpheader * icmp = (struct icmpheader *)
                            (packet + sizeof(struct ethheader));  
    struct tcpheader * tcp = (struct tcpheader *)
                            (packet + sizeof(struct ethheader));     

    printf("     Source IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));   
    // printf("Ethernet shost: %u\n", ether->ether_shost);   
    // printf("Ethernet dhost: %u\n", ether->ether_dhost); 
    printf("Ethernet shost: %x\n", ether->ether_shost);   
    printf("Ethernet dhost: %x\n", ether->ether_dhost); 
   

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("  Protocol: TCP\n");
            printf(" TCP SPORT: %d\n", tcp->tcp_sport);
            printf(" TCP DPORT: %d\n", tcp->tcp_dport);
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            printf("ICMP checksum: %d\n", icmp->icmp_chksum);
            // printf("ICMP checksum: %d\n", icmp->icmp_seq);
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";   // tcp, udp whatever I need
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name ens33
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