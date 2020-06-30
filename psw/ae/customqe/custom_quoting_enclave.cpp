/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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


#include <sgx_secure_align.h>
#include <sgx_random_buffers.h>
#ifndef __linux__
#include "targetver.h"
#endif

#include "se_types.h"
#include "sgx_quote.h"
#include "aeerror.h"
#include "sgx_tseal.h"
#include "sgx_lfence.h"
#include "epid_pve_type.h"
#include "sgx_utils.h"
#include "custom_quoting_enclave_t.c"
#include "sgx_tcrypto.h"
#include "se_sig_rl.h"
#include "se_ecdsa_verify_internal.h"
#include "se_quote_internal.h"
#include "pve_qe_common.h"
#include "byte_order.h"
#include "util.h"
#include "qsdk_pub.hh"
#include "isk_pub.hh"
#include "epid/member/api.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "epid/member/software_member.h"
#include "epid/member/src/write_precomp.h"
#include "epid/member/src/signbasic.h"
#include "epid/member/src/nrprove.h"
#ifdef __cplusplus
}
#endif

#if !defined(SWAP_4BYTES)
#define SWAP_4BYTES(u32)                                                    \
    ((uint32_t)(((((unsigned char*)&(u32))[0]) << 24)                       \
                + ((((unsigned char*)&(u32))[1]) << 16)                     \
                + ((((unsigned char*)&(u32))[2]) << 8)                      \
                + (((unsigned char*)&(u32))[3])))
#endif

// Start from 1, and it's little endian.
#define QE_QUOTE_VERSION        2

#define QE_AES_IV_SIZE          12
#define QE_AES_KEY_SIZE         16
#define QE_OAEP_SEED_SIZE       32

/* One field in sgx_quote_t(signature_len) is not part of the quote_body need
   to be signed by EPID. So we need to minus sizeof(uint32_t). */
#define QE_QUOTE_BODY_SIZE  (sizeof(sgx_quote_t) - sizeof(uint32_t))

/*
 * External function used to get quote. Prefix "emp_" means it is a pointer
 * points memory outside enclave.
 *
 * @param p_enclave_report[in] The application enclave's report.
 * @param p_nonce[in] Pointer to nonce.
 * @param p_qe_report[out] Pointer to QE report, which reportdata is
 *                         sha256(nonce || quote)
 * @param emp_quote[out] Pointer to the output buffer for quote.
 * @param quote_size[in] The size of emp_quote, in bytes.
 * @return ae_error_t AE_SUCCESS for success, otherwise for errors.
 */
uint32_t get_quote(
    const sgx_report_t *p_enclave_report,
    const sgx_quote_nonce_t *p_nonce,
    const sgx_target_info_t *p_app_enclave_target_info,
    sgx_report_t *p_qe_report,
    uint8_t *emp_quote,
    uint32_t quote_size)
{
    ae_error_t ret = AE_SUCCESS;
    sgx_quote_t quote_body;
    uint64_t sign_size = 0;
    sgx_status_t se_ret = SGX_SUCCESS;
    uint64_t required_buffer_size = 0;

    sgx_report_data_t qe_report_data = {{0}};
    sgx_target_info_t report_target;

    memset(&quote_body, 0, sizeof(quote_body));
    memset(&report_target, 0, sizeof(report_target));


    /* Actually, some cases here will be checked with code generated by
       edger8r. Here we just want to defend in depth. */
    if((NULL == p_enclave_report)
       || (NULL == emp_quote)
       || (!quote_size))
        return QE_PARAMETER_ERROR;

    if(!p_nonce && p_qe_report)
        return QE_PARAMETER_ERROR;
    if(p_nonce && !p_qe_report)
        return QE_PARAMETER_ERROR;

    //
    // for user_check SigRL input
    // based on quote_size input parameter
    //
    sgx_lfence();

    if(!sgx_is_outside_enclave(emp_quote, quote_size))
        return QE_PARAMETER_ERROR;

    if(!sgx_is_within_enclave(p_enclave_report, sizeof(*p_enclave_report)))
        return QE_PARAMETER_ERROR;
    /* If the code reach here, if p_nonce is NULL, then p_qe_report will be
       NULL also. So we only check p_nonce here.*/
    if(p_nonce)
    {
        /* Actually Edger8r will alloc the buffer within EPC, this is just kind
           of defense in depth. */
        if(!sgx_is_within_enclave(p_nonce, sizeof(*p_nonce)))
            return QE_PARAMETER_ERROR;
        if(!sgx_is_within_enclave(p_qe_report, sizeof(*p_qe_report)))
            return QE_PARAMETER_ERROR;
    }

    /* Verify the input report. */
    if(SGX_SUCCESS != sgx_verify_report(p_enclave_report))
        return QE_PARAMETER_ERROR;

    required_buffer_size = SE_QUOTE_LENGTH_WITHOUT_SIG + sign_size;

    /* We should make sure the buffer size is big enough. */
    if(quote_size < required_buffer_size)
    {
        ret = QE_PARAMETER_ERROR;
        goto CLEANUP;
    }

    //
    // for user_check SigRL input
    // based on n2 field in SigRL
    //
    sgx_lfence();

    /* Copy the data in the report into quote body. */
    memset(emp_quote, 0, quote_size);
    quote_body.version = 3;

    // Get the QE's report.
    se_ret = sgx_create_report(p_app_enclave_target_info, &qe_report_data, p_qe_report);
    if(SGX_SUCCESS != se_ret)
    {
        ret = QE_PARAMETER_ERROR;
        goto CLEANUP;
    }

    // Copy the incoming report into Quote body.
    memcpy(&quote_body.report_body, &(p_enclave_report->body),
           sizeof(quote_body.report_body));
    /* Because required_buffer_size is larger than signature_len, so if we
       get here, then no integer overflow will ocur. */
    quote_body.signature_len = (uint32_t)(sizeof(se_wrap_key_t)
                               + QUOTE_IV_SIZE
                               + sizeof(uint32_t)
                               + sign_size
                               + sizeof(sgx_mac_t));

    memcpy(emp_quote, &quote_body, sizeof(sgx_quote_t));

CLEANUP:
    return ret;
}
