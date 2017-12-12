#include <iostream>
#include <sstream>

#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/syscall.h>

uid_t drop_uid;

void* some_thread(void *par)
{
	(void)par;

	// drop this thread's privileges to the given uid, this requires that
	// it's a valid user.
	int res = syscall(SYS_setuid, drop_uid);

	if( res != 0 )
	{
		std::cerr << "Failed to drop privs: " << strerror(errno) << std::endl;
		return nullptr;
	}

	while( true )
	{
		usleep(1000 * 1000 * 5);
	}

	return nullptr;
}

int main(const int argc, const char **argv)
{
	pthread_t pt;

	if( argc != 2 )
	{
		std::cerr << argv[0] << ": <UID>\n";
		return 1;
	}

	std::stringstream ss;
	ss.str(argv[1]);
	ss >> drop_uid;
	if( ss.fail() )
	{
		std::cerr << argv[1] << ": Not an integer\n";
		return 1;
	}

	if( pthread_create(&pt, nullptr, &some_thread, nullptr) != 0 )
	{
		std::cerr << "Failed to create thread: " << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "Created thread." << std::endl;
        std::cout << "Running (" << getpid() << "), ^C to exit." << std::endl;

	void *ret = nullptr;
	if( pthread_join(pt, &ret) != 0 )
	{
		std::cerr << "Failed to join thread: " << strerror(errno) << std::endl;
	}

	return 0;
}
