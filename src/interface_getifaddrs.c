#include <sys/types.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include "interface.h"

bool get_interface_addr4(const char *if_name,struct in_addr *if_addr) {
	struct ifaddrs *addrs=NULL,*tmp=NULL;
	bool found=false;
	getifaddrs(&addrs);
	tmp=addrs;
	while(tmp) {
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET) {
#ifdef __clang__
			#pragma clang diagnostic push
			#pragma clang diagnostic ignored "-Wcast-align"
#endif
			struct sockaddr_in *addr_in = (struct sockaddr_in *)tmp->ifa_addr;
#ifdef __clang__
			#pragma clang diagnostic pop
#endif
			if (strcmp(if_name,tmp->ifa_name) == 0 ) {
				if_addr->s_addr = addr_in->sin_addr.s_addr;
				found=true;
				break;
			}
		}
		tmp = tmp->ifa_next;
	}
	freeifaddrs(addrs);
	return found;
}
