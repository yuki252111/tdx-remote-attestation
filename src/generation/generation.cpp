/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "tdx_attest.h"
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif
#define log(msg, ...)                             \
    do                                            \
    {                                             \
        printf("[TDX] " msg "\n", ##__VA_ARGS__); \
        fflush(stdout);                           \
    } while (0)

    int tdx_free_quote(
        uint8_t *p_quote)
    {
        return tdx_att_free_quote(p_quote);
    }

    int tdx_get_quote(const uint8_t *data, uint32_t data_len,
                      uint8_t **p_quote_buf, uint32_t *quote_size)
    {
        log("Info: tdx_get_quote start!");
        // generation report
        tdx_report_data_t report_data = {{0}};
        memcpy(report_data.d, data, data_len);
        tdx_report_t tdx_report = {{0}};
        int ret = tdx_att_get_report(&report_data, &tdx_report);
        if (TDX_ATTEST_SUCCESS != ret)
        {
            log("Error: tdx_att_get_report failed %d", ret);
            return ret;
        }
        // generation quota
        tdx_uuid_t selected_att_key_id = {{0}};
        ret = tdx_att_get_quote(&report_data, NULL, 0, &selected_att_key_id,
                                p_quote_buf, quote_size, 0);
        if (TDX_ATTEST_SUCCESS != ret)
        {
            log("Error: failed to get the quote %d\n", ret);
            return ret;
        }
        log("Info: tdx_att_get_quote success");
        return TDX_ATTEST_SUCCESS;
    }
#ifdef __cplusplus
}
#endif