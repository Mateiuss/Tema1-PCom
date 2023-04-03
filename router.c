#include "headers.h"

#define MAXSIZE_RTABLE 100000

queue packet_q;

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry * cache_arp;
int mtable_len;

struct arp_entry* get_mac_entry(uint32_t daddr)
{
	for (int i = 0; i < mtable_len; i++) {
		if (cache_arp[i].ip == daddr) {
			return cache_arp + i;
		}
	}

	return NULL;
}

uint32_t string_ip_to_int(char *ip)
{
	uint32_t result = 0;
	char *token = strtok(ip, ".");
	int i = 0;
	while (token != NULL) {
		result += atoi(token) << (8 * (3 - i));
		token = strtok(NULL, ".");
		i++;
	}

	return result;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// My initiations
	packet_q = queue_create();

	rtable = malloc(sizeof(struct route_table_entry) * MAXSIZE_RTABLE);
	rtable_len = read_rtable(argv[1], rtable);

	struct Trie *root = newTrie();
	add_all_routes(root, rtable, rtable_len);

	cache_arp = malloc(sizeof(struct arp_entry) * 100);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (eth_hdr->ether_type == htons(IPV4)) {
			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

			// Verific daca adresa de destinatie este a mea
			char *my_ip = get_interface_ip(interface);
			uint32_t my_ip_int = string_ip_to_int(my_ip);

			if (ntohl(ip_hdr->daddr) == my_ip_int) {
				send_ICMP_Reply(interface, buf, len, my_ip_int);

				continue;
			}

			// Verific checksum-ul
			uint16_t check_checksum = checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len));
			if (check_checksum != 0) {
				continue;
			}

			// TTL
			if (ip_hdr->ttl <= 1) {
				send_ICMP_Error(interface, 11, 0, htonl(my_ip_int), ip_hdr->saddr, eth_hdr->ether_shost);
				continue;
			}

			(ip_hdr->ttl)--;

			struct route_table_entry *best_address = longest_prefix_match(root, ip_hdr->daddr);

			if (!best_address) {
				send_ICMP_Error(interface, 3, 0, htonl(my_ip_int), ip_hdr->saddr, eth_hdr->ether_shost);
				continue;
			}

			// Update checksum
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len)));

			get_interface_mac(best_address->interface, eth_hdr->ether_shost);

			struct arp_entry *dmac = get_mac_entry(best_address->next_hop);
			if (!dmac) {
				// Save the packet in queue

				char *buf_copy = malloc(MAX_PACKET_LEN);
				memcpy(buf_copy, buf, len);
				queue_enq(packet_q, (void *)buf_copy);

				// Now I have to send an ARP request

				char request[MAX_PACKET_LEN];

				// Ethernet header
				struct ether_header eth;
				eth.ether_type = htons(ARP);
				get_interface_mac(best_address->interface, eth.ether_shost);
				for (int i = 0; i < 6; i++) {
					eth.ether_dhost[i] = (unsigned char)(-1);
				}

				// ARP header
				struct arp_header arp_hdr;
				arp_hdr.htype = htons((uint16_t)1);
				arp_hdr.ptype = htons((uint16_t)IPV4);
				arp_hdr.hlen = 6;
				arp_hdr.plen = 4;
				arp_hdr.op = htons((uint16_t)1);
				memcpy(arp_hdr.sha, eth.ether_shost, 6);
				uint32_t my_ip = htonl(string_ip_to_int(get_interface_ip(best_address->interface)));
				memcpy(&arp_hdr.spa, &my_ip, 4);
				memset(arp_hdr.tha, 0, 6);
				arp_hdr.tpa = best_address->next_hop;

				// Copy the headers into the request
				memcpy(request, &eth, sizeof(struct ether_header));
				memcpy(request + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

				// Send the request
				send_to_link(best_address->interface, request, sizeof(struct ether_header) + sizeof(struct arp_header));
				continue;
			}

			memcpy(eth_hdr->ether_dhost, dmac->mac, 6);

			send_to_link(best_address->interface, buf, len);
		} else if(eth_hdr->ether_type == htons(ARP)) {  // ARP
			struct arp_header* arp = (struct arp_header *) (buf + sizeof(struct ether_header));

			if (ntohs(arp->op) == 2) {  // ARP reply
				queue temp = queue_create();

				cache_arp[mtable_len].ip = arp->spa;
				memcpy(&cache_arp[mtable_len++].mac, arp->sha, 6);

				while (!queue_empty(packet_q)) {
					char *packet = (char *)queue_deq(packet_q);

					struct ether_header* packet_eth = (struct ether_header*)packet;
					struct iphdr* packet_ip = (struct iphdr*)(packet + sizeof(struct ether_header));

					struct route_table_entry *best_address =  longest_prefix_match(root, packet_ip->daddr);

					if (arp->spa == best_address->next_hop) {
						memcpy(packet_eth->ether_dhost, arp->sha, 6);

						send_to_link(best_address->interface, packet, ntohs(packet_ip->tot_len) + sizeof(struct ether_header));
						free(packet);
					} else {
						queue_enq(temp, (void*)packet);
					}
				}

				free(packet_q);
				packet_q = temp;
			} else if (ntohs(arp->op) == 1) { // ARP request
				char *my_ip = get_interface_ip(interface);

				uint32_t my_ip_int = string_ip_to_int(my_ip);

				uint32_t ip = ntohl(arp->tpa);
				if (memcmp(&ip, &my_ip_int, 4) != 0) {  // Check if the request is for me
					continue;
				}
				uint32_t tmp_ip = arp->tpa;

				arp->tpa = arp->spa;
				memcpy(arp->tha, arp->sha, 6);

				arp->spa = tmp_ip;
				get_interface_mac(interface, arp->sha);

				memcpy(eth_hdr->ether_shost, arp->sha, 6);
				memcpy(eth_hdr->ether_dhost, arp->tha, 6);

				arp->op = htons((uint16_t)2);

				send_to_link(interface, buf, len);
			}
		}

	}

	free(cache_arp);
	free(rtable);
	free(root);
}

