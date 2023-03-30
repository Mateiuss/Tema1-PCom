#pragma once
#include "headers.h"

void send_ICMP_Error(int interface, uint8_t type, uint8_t code, uint32_t saddr, uint32_t daddr, uint8_t* dmac);
void send_ICMP_Reply(int interface, char *buf, int len, int my_ip_int);