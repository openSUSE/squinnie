#include <iostream>
#include <sstream>

#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <cap-ng.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

uid_t drop_uid;

void* some_thread(void *par)
{
	(void)par;
        
        // at first we need to get our caps
        // in this case we use CAP_SETUID, as SETUID fails otherwise
	capng_clear(CAPNG_SELECT_BOTH);
	capng_update(CAPNG_ADD, (capng_type_t)(CAPNG_EFFECTIVE|CAPNG_PERMITTED), CAP_SETUID);
	capng_apply(CAPNG_SELECT_BOTH);
        
        // this call preserves our caps through the drops
        prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

        // now drop our uid
        // both threads need to drop it, as this is to test if the scanner
        // spots the differences in caps only
        if(syscall(SYS_setuid, drop_uid)) 
        {
            std::cerr << "Failed to drop privs in thread: " << strerror(errno) << std::endl;
            return nullptr;
        }

        // wait for ^C
	while( true )
	{
		usleep(1000 * 1000 * 5);
	}

	return nullptr;
}

int main(const int argc, const char **argv)
{
	pthread_t pt;
        
        // we need an UID to drop to
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

        // start our thread which will take the capabilites
	if( pthread_create(&pt, nullptr, &some_thread, nullptr) != 0 )
	{
		std::cerr << "Failed to create thread: " << strerror(errno) << std::endl;
		return 2;
	}

        // drop our uid - the scanner ignores caps on root processes
	if(syscall(SYS_setuid, drop_uid)) 
        {
            std::cerr << "Failed to drop privs: " << strerror(errno) << std::endl;
            return 2;
        }

	std::cout << "Created thread." << std::endl;
	std::cout << "Running (" << getpid() << "), ^C to exit." << std::endl;

        // wait for the thread to return
	void *ret = nullptr;
	if( pthread_join(pt, &ret) != 0 )
	{
		std::cerr << "Failed to join thread: " << strerror(errno) << std::endl;
	}

	return 0;
}
