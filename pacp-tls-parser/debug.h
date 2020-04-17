#pragma once
#include "stdio.h"
#include "stdarg.h"
//#include <pthread.h>
class Debug
{
public:
	Debug(void)
	{};
public:
	~Debug(void)
	{};
public:
	void DebugPrint(int debugLevel, const char* format, ...)
	{
		if (debugLevel <= m_debugLevel)
		{
			va_list arg;
			va_start(arg, format);
			vprintf(format, arg);
			va_end(arg);
		}

	};

	void SetDebugLevel(int level)
	{
		m_debugLevel = level;
	};

private:
	int m_debugLevel;
};


extern Debug DebugOut;
