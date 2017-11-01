#ifdef _MSC_VER
#pragma warning(disable : 4267 4102)  // conversion from size_t, unreferenced label
#endif /* _MSC_VER */

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include <windows.h>

#include <gittest/log.h>

/* http://stackoverflow.com/questions/1394250/detect-program-termination-c-windows/1400395#1400395 */

/* NOTE: avoid using logging functions such as GS_GOTO_CLEAN() inside crash handler ! */

LONG WINAPI gs_log_crash_handler_unhandled_exception_filter_(struct _EXCEPTION_POINTERS *ExceptionInfo);

LONG WINAPI gs_log_crash_handler_unhandled_exception_filter_(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	//DebugBreak();
	/* not much to do about errors here presumably */
	if (!!gs_log_crash_handler_dump_global_log_list_suffix("", strlen("")))
		printf("[ERROR] 0 inside crash handler gs_log_crash_handler_unhandled_exception_filter_\n");

	if (!!gs_log_list_call_func_dump_extra_global_lowlevel())
		printf("[ERROR] 1 inside crash handler gs_log_crash_handler_unhandled_exception_filter_\n");

	return EXCEPTION_CONTINUE_SEARCH;
}

int gs_log_crash_handler_setup()
{
	int r = 0;

	SetUnhandledExceptionFilter(gs_log_crash_handler_unhandled_exception_filter_);

clean:

	return r;
}
