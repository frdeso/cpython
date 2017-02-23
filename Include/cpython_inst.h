#ifndef CPYTHON_INSTRUMENTATION_H
#define CPYTHON_INSTRUMENTATION_H


#if defined(WITH_LTTNGUST)
#include <lttng/tracepoint.h>
#include <pylttngust_probes.h>
#define PyTrace(name, ...) \
	do_tracepoint(python, name, __VA_ARGS__)
#define PyTraceEnabled(name) \
	tracepoint_enabled(python, name)

#elif defined(WITH_DTRACE)

#define SDT_USE_VARIADIC
#include "pydtrace_probes.h"

#define PyTrace(name, ...) \
	STAP_PROBEV(python, name, ##__VA_ARGS__)
#define PyTraceEnabled(name) \
	__builtin_expect (python_##name##_semaphore, 0)
#else
/* Without DTrace or UST, compile to nothing. */
#define PyTrace(...) {}
#define PyTraceEnabled(...) (0)

#endif
#endif //CPYTHON_INSTRUMENTATION_H
