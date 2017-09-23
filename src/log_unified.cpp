#include <stdint.h>
#include <cstdio>

#include <sstream>
#include <iomanip>

#include <gittest/misc.h>

/** @sa
       ::gs_log_unified_create
	   ::gs_log_unified_destroy
	   ::gs_log_unified_message_log
*/
struct GsLogUnified {
};

int gs_log_unified_create(struct GsLogUnified **oLogUnified)
{
	*oLogUnified = new GsLogUnified();
	return 0;
}

int gs_log_unified_destroy(struct GsLogUnified *LogUnified)
{
	GS_DELETE(&LogUnified, GsLogUnified);
	return 0;
}

int gs_log_unified_message_log(
	GsLogUnified *LogUnified,
	const char *Prefix,
	uint32_t Level,
	const char *MsgBuf,
	uint32_t MsgSize,
	const char *CppFile,
	int CppLine)
{
	std::stringstream ss;

	if (strcmp(MsgBuf, "CLEAN") == 0) {
		std::string CF(CppFile);
		const size_t FS = CF.find_last_of('/');
		const size_t BS = CF.find_last_of('\\');
		const size_t From = FS != std::string::npos ? FS+1 : (BS != std::string::npos ? BS+1 : 0);
		CF = CF.substr(From);
		ss << "[" << std::setw(30) << CF << ":" << std::setw(5) << CppLine << "] ";
	}

	ss  << "[" << std::string(Prefix) << "] "
		<< "[" << std::string(MsgBuf, MsgSize) << "]"
		<< std::endl;

	/* write to stdout as debug aid */
	printf("%s", ss.str().c_str());

	return 0;
}
