#include <netinet/in.h>
#include <stdbool.h>

#ifndef MY_INTERFACE
#define MY_INTERFACE
bool get_interface_addr4(const char *if_name,struct in_addr *if_addr);
#endif // MY_INTERFACE
