#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER python

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./pylttngust_probes.h"

#if !defined(_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TP_H

#include <lttng/tracepoint.h>

#endif

#include <lttng/tracepoint-event.h>

TRACEPOINT_EVENT(
        python,
        line,
        TP_ARGS(
            const char *, co_filename,
            const char *, co_name,
            int, line_no
            ),
        TP_FIELDS(
            ctf_string(co_filename, co_filename)
            ctf_string(co_name, co_name)
            ctf_integer(int, line_no, line_no)
            )
        )
TRACEPOINT_EVENT(
        python,
        function__entry,
        TP_ARGS(const char *, co_filename,
            const char *, co_name,
            int, line_no),
        TP_FIELDS(
            ctf_string(co_filename, co_filename)
            ctf_string(co_name, co_name)
            ctf_integer(int, line_no, line_no)
            )
        )
TRACEPOINT_EVENT(
        python,
        function__return,
        TP_ARGS(const char *, co_filename,
            const char *, co_name,
            int, line_no),
        TP_FIELDS(
            ctf_string(co_filename, co_filename)
            ctf_string(co_name, co_name)
            ctf_integer(int, line_no, line_no)
            )
        )
TRACEPOINT_EVENT(
        python,
        gc__start,
        TP_ARGS(
            int, generation
            ),
        TP_FIELDS(
            ctf_integer(int, generation, generation)
            )
        )
TRACEPOINT_EVENT(
        python,
        gc__done,
        TP_ARGS(
            long, collected
            ),
        TP_FIELDS(
            ctf_integer(long int, collected, collected)
            )
        )
