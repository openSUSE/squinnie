#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mqueue.h>
#include <fcntl.h>
#include <unistd.h>
#include <semaphore.h>

#include "ipc_common.h"
#include <iostream>

/*
 * this test program sets up some POSIX IPC objects for inspection by Squinnie.
 *
 * for the related APIs see `man 7 sem_overview shm_overview mq_overview`
 *
 * possible invocations:
 *
 * posix_ipc <type> <mode> <name>
 *
 * <type>: queue, semaphore, shm
 *
 * <mode>: create (create the object), attach (attach to an existing object)
 *
 * <name>: a basename without slashes that identifies the IPC object
 */

namespace
{

class PosixHandler
{
public:
	PosixHandler(const int argc, const char **argv)
	{
		for( int i = 1; i < argc; i++ )
		{
			m_args.push_back(argv[i]);
		}
	}

	void parseArgs()
	{
		if( m_args.size() != 3 )
		{
			std::cout << "type: queue, semaphore, shm\n";
			std::cout << "mode: create, attach\n";
			std::cout << "name: basename identifier\n";
			std::cout << "\n";
			throw Exception(
				"Expected the parameters <type>, "
					"<mode>, <name>"
			);
		}

		const auto &type = m_args.at(0);
		const auto &mode = m_args.at(1);
		const auto &name = m_args.at(2);

		m_type = parseType(type);
		m_mode = parseMode(mode);
		m_create = m_mode == CREATE;
		m_name = "/" + name;
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
		m_mqd = mq_open(
			m_name.c_str(), getOpenFlags(), m_create_mode, nullptr
		);
		checkAction(m_mqd, (mqd_t)-1, "queue");
	}

	void performShmAction()
	{
		m_shm_fd = shm_open(
				m_name.c_str(), getOpenFlags(), m_create_mode
		);
		checkAction(m_shm_fd, -1, "shm");
	}

	void performSemaphoreAction()
	{
		m_sem = sem_open(m_name.c_str(), getOpenFlags(),
				m_create_mode, 1);
		checkAction(m_sem, SEM_FAILED, "semaphore");
	}

	void close()
	{
		int ret;

		if( !m_create )
			return;

		switch( m_type )
		{
		case QUEUE:
			ret = mq_close(m_mqd);
			ret = ret == 0 && mq_unlink(m_name.c_str());
			break;
		case SHM:
			ret = ::close(m_shm_fd);
			ret = ret == 0 && shm_unlink(m_name.c_str());
			break;
		case SEMAPHORE:
			ret = sem_close(m_sem);
			ret = ret == 0 && sem_unlink(m_name.c_str());
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

	template <typename T>
	void checkAction(T fd, T bad, const char *label)
	{
		if( fd == bad )
		{
			std::string err("Failed to perform ");
			err += label;
			err += " action";
			throw SysException(err);
		}

		std::cout << (m_create ? "Created" : "Attached")
			<< " " << label << "\n";
	}

	int getOpenFlags() const
	{
		auto ret = 0;

		if( m_create )
		{
			ret = O_CREAT | O_EXCL;
		}

		return ret;
	}

protected:
	StringVector m_args;
	Type m_type;
	Mode m_mode;
	std::string m_name;
	sem_t *m_sem = nullptr;
	int m_shm_fd = -1;
	mqd_t m_mqd = -1;
	const int m_create_mode = 0600;
	bool m_create = false;
};

} // end ns

int main(const int argc, const char **argv)
{
	try
	{
		PosixHandler handler(argc, argv);
		handler.run();
		return 0;
	}
	catch( const std::exception &ex )
	{
		std::cerr << "Error: " << ex.what() << std::endl;
		return 1;
	}
}

