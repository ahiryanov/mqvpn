// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 mp0rta and mqvpn contributors

#undef NDEBUG
#include <assert.h>
#include "mqvpn_xquic_err_names.h"

_Static_assert(XQC_ESTREAM_RESET == 626, "update the reset log matcher");

static int
routine(xqc_log_level_t lvl, const char *line, size_t size)
{
    char msg[600];
    mqvpn_xquic_annotate_err_codes(line, size, msg, sizeof(msg));
    return mqvpn_xquic_log_is_routine(lvl, msg);
}

#define CHECK(level, line, expected) \
    assert(routine(level, line, sizeof(line) - 1) == (expected))

int
main(void)
{
    CHECK(XQC_LOG_ERROR, "|xqc_h3_stream_process_data|xqc_stream_recv error|-626|", 1);
    CHECK(XQC_LOG_ERROR,
          "|xqc_h3_stream_process_blocked_data|xqc_stream_recv error|-626|", 1);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|close_msg:finished|err:0|", 1);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|close_msg:local reset|err:268|", 1);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:0x10c|", 1);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:262|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:267|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:999|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_conn_destroy|err:0|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|path_err:0|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:|", 0);
    CHECK(XQC_LOG_REPORT, "|xqc_h3_request_destroy|err:0junk|", 0);
    CHECK(XQC_LOG_ERROR, "|xqc_h3_stream_process_data|xqc_stream_recv error|-625|", 0);
    CHECK(XQC_LOG_ERROR, "|xqc_h3_stream_process_data|xqc_stream_recv error|-6260|", 0);
    CHECK(XQC_LOG_FATAL, "|xqc_h3_stream_process_data|xqc_stream_recv error|-626|", 0);
    CHECK(XQC_LOG_ERROR, "|other_function|xqc_stream_recv error|-626|", 0);
    /* Log buffers need not be terminated; do not inspect bytes past size. */
    const char bounded[] = "|xqc_h3_request_destroy|err:268|";
    assert(routine(XQC_LOG_REPORT, bounded, sizeof(bounded) - 2) == 0);
    assert(routine(XQC_LOG_REPORT, bounded, sizeof(bounded) - 1) == 1);
    assert(routine(XQC_LOG_REPORT, bounded, 0) == 0);
    puts("xquic routine log filtering: passed");
    return 0;
}
