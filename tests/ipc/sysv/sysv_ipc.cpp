#include <iostream>

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/msg.h>
#include <sys/shm.h>

#include "ipc_common.h"

/*
 * this test program sets up some SystemV IPC objects for inspection by
 * Hamster.
 *
 * for the related APIs see `man 7 svipc`
 *
 * possible invocations:
 *
 * sys_ipc <type> <mode> <path-id>
 *
 * <type>: queue, semaphore, shm
 *
 * <mode>: create (create the object), attach (attach to an existing object)
 *
 * <path-id>: a valid path which will be used as identifier for
 * creating/attaching objects. the pointed to file will not be used except for
 * the purposes of calculating a suitable IPC address.
 */

namespace
{

class SysvHandler
{
public:
	SysvHandler(const int argc, const char **argv)
	{
		for( int i = 1; i < argc; i++ )
		{
			m_args.push_back(argv[i]);
		}
	}

	key_t getKey(const std::string &path)
	{
		auto ret = ftok(path.c_str(), 0x47);

		if( ret == -1 )
		{
			throw SysException(
				std::string("Failed to get IPC key from ") + path
			);
		}

		return ret;
	}

	void parseArgs()
	{
		if( m_args.size() != 3 )
		{
			std::cout << "type: queue, semaphore, shm\n";
			std::cout << "mode: create, attach\n";
			std::cout << "path-id: a valid path object used as "
				"a basis for the IPC identifier\n";
			std::cout << "\n";
			throw Exception(
				"Expected the parameters <type>, "
					"<mode>, <path-id>"
			);
		}

		const auto &type = m_args.at(0);
		const auto &mode = m_args.at(1);
		const auto &path = m_args.at(2);

		m_type = parseType(type);
		m_mode = parseMode(mode);
		m_create = m_mode == CREATE;
		m_key = getKey(path);
	}

	void run()
	{
		parseArgs();
		performAction();
		waitFinish();
		close();
	}

	void waitFinish()
	{
		std::cout << "Waiting for ENTER before quitting." << std::endl;
		std::string line;
		std::getline(std::cin, line, '\n');
	}

	void performQueueAction()
	{
		const int flags = getFlags();

		m_id = msgget(m_key, flags);
		checkAction("queue");
	}

	void performShmAction()
	{
		const int flags = getFlags();

		m_id = shmget(m_key, 4096, flags);
		checkAction("shm");
	}

	void performSemaphoreAction()
	{
		const int flags = getFlags();

		m_id = semget(m_key, 1, flags);
		checkAction("semaphore");
	}

	void close()
	{
		int ret;

		if( !m_create )
			return;

		switch( m_type )
		{
		case QUEUE:
			ret = msgctl(m_id, IPC_RMID, NULL);
			break;
		case SHM:
			ret = shmctl(m_id, IPC_RMID, NULL);
			break;
		case SEMAPHORE:
			ret = semctl(m_id, 1, IPC_RMID);
			break;
		}

		if( ret == -1 )
		{
			throw SysException("Failed to close object");
		}
	}

	void performAction()
	{
		switch( m_type )
		{
		case QUEUE:
			performQueueAction();
			break;
		case SHM:
			performShmAction();
			break;
		case SEMAPHORE:
			performSemaphoreAction();
			break;
		}
	}


	void addCreateFlags(int &flags) const
	{
		flags |= m_create_mode | IPC_CREAT | IPC_EXCL;
	}

	int getFlags() const
	{
		int ret = 0;

		if( m_create )
			addCreateFlags(ret);

		return ret;
	}

	void checkAction(const char *label)
	{
		if( m_id == -1 )
		{
			std::string err("Failed to perform ");
			err += label;
			err += " action";
			throw SysException(err);
		}

		std::cout << (m_create ? "Created" : "Attached")
			<< " " << label << "\n";
	}

protected:
	StringVector m_args;
	Type m_type;
	Mode m_mode;
	key_t m_key;
	int m_id = 0;
	const int m_create_mode = 0600;
	bool m_create = false;
};

} // end ns

int main(const int argc, const char **argv)
{
	try
	{
		SysvHandler handler(argc, argv);
		handler.run();
		return 0;
	}
	catch( const std::exception &ex )
	{
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}

