#include <stdint.h>
#include <cstdio>

#include <sstream>

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
	ss  << "[" + std::string(Prefix) + "] "
		<< "[" + std::string(MsgBuf, MsgSize) << "]"
		<< std::endl;

	/* write to stdout as debug aid */
	printf("%s", ss.str().c_str());

	return 0;
}
