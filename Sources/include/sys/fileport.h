#ifndef _SYS_FILEPORT_H
#define _SYS_FILEPORT_H

#include <sys/types.h>
#include <mach/mach_types.h>

typedef mach_port_t fileport_t;

fileport_t fileport_makeport(int fd, int *osir_return);
int fileport_makefd(fileport_t port);
void fileport_releaseport(fileport_t port);

#endif
