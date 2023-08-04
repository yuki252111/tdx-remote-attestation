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

#include "sgx_dcap_quoteverify.h"
#include "sgx_ql_quote.h"
#include <assert.h>
#include <cstring>
#include <fstream>
#include <stdio.h>
#include <string>
#include <vector>

using namespace std;
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

    typedef union _supp_ver_t
    {
        uint32_t version;
        struct
        {
            uint16_t major_version;
            uint16_t minor_version;
        };
    } supp_ver_t;

    /**
     * @param quote - ECDSA quote buffer
     * @param use_qve - Set quote verification mode
     *                   If true, quote verification will be performed by Intel QvE
     *                   If false, quote verification will be performed by untrusted QVL
     */

    int ecdsa_quote_verification(const uint8_t *quote, const uint32_t quote_size)
    {

        int ret = 0;
        time_t current_time = 0;
        quote3_error_t dcap_ret = SGX_QL_ERROR_UNEXPECTED;
        uint32_t collateral_expiration_status = 1;
        sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

        tee_supp_data_descriptor_t supp_data;

        // You can also set specify a major version in this structure, then we will always return supplemental data of the major version
        // set major verison to 0 means always return latest supplemental data
        memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));

        supp_ver_t latest_ver;

        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        dcap_ret = tee_get_supplemental_data_version_and_size(quote,
                                                              quote_size,
                                                              &latest_ver.version,
                                                              &supp_data.data_size);

        if (dcap_ret == SGX_QL_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t))
        {
            log("Info: tee_get_quote_supplemental_data_version_and_size successfully returned.");
            log("Info: latest supplemental data major version: %d, minor version: %d, size: %d", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
            supp_data.p_data = (uint8_t *)malloc(supp_data.data_size);
            if (supp_data.p_data != nullptr)
            {
                memset(supp_data.p_data, 0, supp_data.data_size);
            }

            // Just print error in sample
            //
            else
            {
                log("Error: Cannot allocate memory for supplemental data.");
                supp_data.data_size = 0;
            }
        }
        else
        {
            if (dcap_ret != SGX_QL_SUCCESS)
                log("Error: tee_get_quote_supplemental_data_size failed: 0x%04x", dcap_ret);

            if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
                log("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");

            supp_data.data_size = 0;
        }

        uint8_t *p_quote_collateral = nullptr;
        uint32_t collateral_size = 0;
        dcap_ret = tee_qv_get_collateral(quote, quote_size, &p_quote_collateral, &collateral_size);
        if (dcap_ret == SGX_QL_SUCCESS)
        {
            log("Info: tee_qv_get_collateral success");
        }
        else
        {
            log("Error: tee_qv_get_collateral failed");
        }

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(nullptr);

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT nullptr, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is nullptr, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = tee_verify_quote(
            quote, quote_size,
            p_quote_collateral,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            nullptr,
            &supp_data);
        if (dcap_ret == SGX_QL_SUCCESS)
        {
            log("Info: App: tee_verify_quote successfully returned.");
        }
        else
        {
            log("Error: App: tee_verify_quote failed: %x", dcap_ret);
            goto cleanup;
        }

        // check verification result
        //
        switch (quote_verification_result)
        {
        case SGX_QL_QV_RESULT_OK:
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if (collateral_expiration_status == 0)
            {
                log("Info: App: Verification completed successfully.");
                ret = 0;
            }
            else
            {
                log("Warning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                ret = 1;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            log("Warning: App: Verification completed with Non-terminal result: %x", quote_verification_result);
            ret = 1;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            log("Error: App: Verification completed with Terminal result: %x", quote_verification_result);
            ret = -1;
            break;
        }

        // check supplemental data if necessary
        //
        if (dcap_ret == SGX_QL_SUCCESS && supp_data.p_data != nullptr && supp_data.data_size > 0)
        {
            sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)supp_data.p_data;

            // you can check supplemental data based on your own attestation/verification policy
            // here we only print supplemental data version for demo usage
            //
            log("Info: Supplemental data Major Version: %d", p->major_version);
            log("Info: Supplemental data Minor Version: %d", p->minor_version);

            // print SA list if exist, SA list is supported from version 3.1
            //
            if (p->version > 3 && strlen(p->sa_list) > 0)
            {
                log("Info: Advisory ID: %s", p->sa_list);
            }
        }

    cleanup:
        if (supp_data.p_data != nullptr)
        {
            free(supp_data.p_data);
        }
        if (p_quote_collateral != nullptr)
        {
            tee_qv_free_collateral(p_quote_collateral);
        }

        return ret;
    }
#ifdef __cplusplus
}
#endif