#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define IPV4 0x0800
#define ARP 0x0806
#define MAXSIZE_RTABLE 100000

queue packet_q;

struct route_table_entry *rtable;
int rtable_len;

struct arp_entry *mtable;
int mtable_len;

int compare (const void *a, const void *b)
{
	struct route_table_entry *c = (struct route_table_entry *)a;
	struct route_table_entry *d = (struct route_table_entry *)b;

	if (c->mask < d->mask) return 1;
	if (c->mask == d->mask) return 0;
	return -1;
}

struct route_table_entry* get_best_route(uint32_t daddr)
{
	for (int i = 0; i < rtable_len; i++) {
		//printf("%x %x %x\n", daddr, daddr & rtable[i].mask, rtable[i].prefix);
		if ((daddr & rtable[i].mask) == rtable[i].prefix) {
			return rtable + i;
		} 
	}

	return NULL;
}

struct arp_entry* get_mac_entry(uint32_t daddr)
{
	for (int i = 0; i < mtable_len; i++) {
		if (mtable[i].ip == daddr) {
			return mtable + i;
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// My initiations
	packet_q = queue_create();

	rtable = malloc(sizeof(struct route_table_entry) * MAXSIZE_RTABLE);
	rtable_len = read_rtable(argv[1], rtable);

	qsort((void *)rtable, rtable_len, sizeof(struct route_table_entry), compare);

	mtable = malloc(sizeof(struct arp_entry) * 100);
	mtable_len = parse_arp_table("arp_table.txt", mtable);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		printf("Packet received!\n");

		if (eth_hdr->ether_type == htons(IPV4)) {
			printf("Packet is IPv4\n");

			// TODO: De facut raspunsul la pachetul pentru mine mai tarziu

			// Verific checksum-ul
			uint16_t check_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
			if (check_checksum != 0) {
				printf("Wrong checksum!\n");
				continue;
			}

			printf("The checksum is ok!\n");

			// TTL
			if (ip_hdr->ttl <= 1) {
				printf("TTL expired\n");

				// TODO: Va trebui sa dau un mesaj de tipul "Time exceeded"

				continue;
			}

			(ip_hdr->ttl)--;

			struct route_table_entry *best_address = get_best_route(ip_hdr->daddr);
			if (!best_address) {
				printf("No next-hop found!\n");
				continue;
			}

			printf("Found a next hop\n");

			uint16_t new_checksum = ~(~ip_hdr->check + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)ip_hdr->ttl) - 1;
			ip_hdr->check = new_checksum;

			get_interface_mac(interface, eth_hdr->ether_shost);

			struct arp_entry *dmac = get_mac_entry(best_address->next_hop);
			if (!dmac) {
				printf("Didn't find the mac entry!\n");
				continue;
			}

			memcpy(eth_hdr->ether_dhost, dmac->mac, 6);

			send_to_link(best_address->interface, buf, len);
		}

	}
}

