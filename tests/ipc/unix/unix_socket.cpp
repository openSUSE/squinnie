#include <iostream>

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

int main(const int argc, const char **argv)
{
	int us = socket(AF_UNIX, SOCK_DGRAM, 0);
	if( us == -1 )
	{
		std::cerr << "failed to create socket: " << strerror(errno) << std::endl;
	}

	close(us);

	return 0;
}

