#include "headers.h"

void send_ICMP_Error(int interface, uint8_t type, uint8_t code, uint32_t saddr, uint32_t daddr, uint8_t* dmac)
{
	char packet[MAX_PACKET_LEN];

	struct icmphdr icmp_hdr;
	icmp_hdr.type = type;
	icmp_hdr.code = code;
	icmp_hdr.checksum = 0;
	icmp_hdr.checksum = htons(checksum((uint16_t *)&icmp_hdr, sizeof(struct icmphdr)));

	struct iphdr ip_hdr;
	ip_hdr.daddr = daddr;
	ip_hdr.saddr = saddr;
	ip_hdr.protocol = IPPROTO_ICMP;
	ip_hdr.tos = 0;
	ip_hdr.frag_off = 0;
	ip_hdr.version = 4;
	ip_hdr.ihl = 5;
	ip_hdr.id = 1;
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.ttl = 64;
	ip_hdr.check = 0;
	ip_hdr.check = htons(checksum((uint16_t *)&ip_hdr, sizeof(struct iphdr)));

	struct ether_header eth_hdr;
	eth_hdr.ether_type = htons(IPV4);
	memcpy(eth_hdr.ether_dhost, dmac, 6);
	get_interface_mac(interface, eth_hdr.ether_shost);

	memcpy(packet, &eth_hdr, sizeof(struct ether_header));
	memcpy(packet + sizeof(struct ether_header), &ip_hdr, sizeof(struct iphdr));
	memcpy(packet + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, packet, sizeof(struct ether_header) + ntohs(ip_hdr.tot_len));
}

void send_ICMP_Reply(int interface, char *buf, int len, int my_ip_int)
{
    struct ether_header *eth_hdr = (struct ether_header *) buf;
    struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    icmp_hdr->type = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = htonl(my_ip_int);
    ip_hdr->ttl = 64;
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

    eth_hdr->ether_type = htons(IPV4);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    get_interface_mac(interface, eth_hdr->ether_shost);

    send_to_link(interface, buf, len);
}