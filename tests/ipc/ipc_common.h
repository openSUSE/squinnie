#include <exception>
#include <vector>
#include <string>

namespace
{

enum Type
{
	QUEUE,
	SEMAPHORE,
	SHM
};

enum Mode
{
	CREATE,
	ATTACH
};

typedef std::vector<std::string> StringVector;

class Exception :
	public std::exception
{
public:
	explicit Exception(const std::string &msg) : m_msg(msg) { }

	const char* what() const throw() override
	{
		return m_msg.c_str();
	}
protected:
	std::string m_msg;
};

class SysException :
	public Exception
{
public:
	explicit SysException(const std::string &msg) :
		Exception(msg),
		m_errno(errno)
	{
		m_msg += ": ";
		m_msg += std::string(strerror(m_errno));
	}

protected:
	int m_errno;
};

Type parseType(const std::string &type)
{
	if( type == "queue" )
		return QUEUE;
	else if( type == "semaphore" )
		return SEMAPHORE;
	else if( type == "shm" )
		return SHM;

	throw Exception(
		std::string("Invalid type encountered: ") + type
	);
}

Mode parseMode(const std::string &mode)
{
	if( mode == "create" )
		return CREATE;
	else if( mode == "attach" )
		return ATTACH;

	throw Exception(
		std::string("Invalid mode encountered: ") + mode
	);
}

} // end ns

