#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "interface.h"
#include <errno.h>

bool get_interface_addr4(const char *if_name,struct in_addr *if_addr) {
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0) {
		printf("%s is %d\n",strerror(errno),s);
		return(false);
	}

	memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name)-1);
	printf("%s\n",ifr.ifr_name);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
	if(ioctl(s, SIOCGIFADDR, &ifr)==-1) {
		close(s);
		return(false);
	}
	close(s);
#ifdef __clang__
		#pragma clang diagnostic push
		#pragma clang diagnostic ignored "-Wcast-align"
#endif
	struct sockaddr_in *addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
#ifdef __clang__
		#pragma clang diagnostic pop
#endif
	if_addr->s_addr = addr_in->sin_addr.s_addr;
	return(true);
}
