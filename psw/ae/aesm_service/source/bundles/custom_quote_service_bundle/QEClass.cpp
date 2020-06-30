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


#include <assert.h>
#include "arch.h"
#include "QEClass.h"
#include "se_memcpy.h"
#include "prof_fun.h"
#include "custom_quoting_enclave_u.h"
#include "metadata.h"
#include <dlfcn.h>

static ae_error_t aesm_get_path(
    const char *p_file_name,
    char *p_file_path,
    size_t buf_size)
{
    if(!p_file_name || !p_file_path)
        return OAL_PARAMETER_ERROR;

    Dl_info dl_info;
    if(0==dladdr(__builtin_return_address(0), &dl_info)||
        NULL==dl_info.dli_fname)
        return AE_FAILURE;
    if(strnlen(dl_info.dli_fname,buf_size)>=buf_size)
        return OAL_PATHNAME_BUFFER_OVERFLOW_ERROR;
    (void)strncpy(p_file_path,dl_info.dli_fname,buf_size);
    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL )
    {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else p_file_path[0] = '\0';
    if(strnlen(p_file_path,buf_size)+strnlen(p_file_name,buf_size)+sizeof(char)>buf_size)
        return OAL_PATHNAME_BUFFER_OVERFLOW_ERROR;
    (void)strncat(p_file_path,p_file_name, strnlen(p_file_name,buf_size));
    return AE_SUCCESS;
}

void CQEClass::before_enclave_load() {
}

ae_error_t CQEClass::load_enclave()
{
    before_enclave_load();

    if(m_enclave_id)
        return AE_SUCCESS;

    sgx_status_t ret;
    ae_error_t ae_err;
    char enclave_path[MAX_PATH]= {0};
    if((ae_err = aesm_get_path("libsgx_customqe_signed.so", enclave_path,
        MAX_PATH))
        !=AE_SUCCESS){
        AESM_DBG_ERROR("fail to get enclave pathname");
        return ae_err;
    }
    int launch_token_update;
    ret = sgx_create_enclave(enclave_path, get_debug_flag(), &m_launch_token,
        &launch_token_update, &m_enclave_id,
        &m_attributes);
    if (ret == SGX_ERROR_NO_DEVICE){
        AESM_DBG_ERROR("AE SERVER NOT AVAILABLE in load enclave: %s",enclave_path);
        return AE_SERVER_NOT_AVAILABLE;
    }
    if(ret == SGX_ERROR_OUT_OF_EPC){
        AESM_DBG_ERROR("No enough EPC to load AE: %s",enclave_path);
        AESM_LOG_ERROR("%s %s", g_event_string_table[SGX_EVENT_OUT_OF_EPC], enclave_path);
        return AESM_AE_OUT_OF_EPC;
    }
    if (ret != SGX_SUCCESS){
        AESM_DBG_ERROR("Create Enclave failed:%d",ret);
        return AE_SERVER_NOT_AVAILABLE;
    }
    AESM_DBG_INFO("enclave %d loaded with id 0X%llX",aesm_enclave_id,m_enclave_id);

    return AE_SUCCESS;
}

extern "C" sgx_status_t sgx_get_metadata(const char* enclave_file, metadata_t *metadata);

uint32_t CQEClass::get_qe_target(
    sgx_target_info_t *p_target,
    sgx_isv_svn_t *p_isvsvn)
{
    ae_error_t ae_err;
    metadata_t metadata;
    char enclave_path[MAX_PATH]= {0};
    if ((NULL == p_target) || (NULL == p_isvsvn))
        return AE_INVALID_PARAMETER;

    /* We need to make sure the QE is successfully loaded */
    assert(m_enclave_id);
    memset(p_target, 0, sizeof(sgx_target_info_t));
    if(SGX_SUCCESS != sgx_get_target_info(m_enclave_id, p_target))
        return AE_FAILURE;

    if((ae_err = aesm_get_pathname(FT_ENCLAVE_NAME, get_enclave_fid(), enclave_path, MAX_PATH)) != AE_SUCCESS){
        AESM_DBG_ERROR("fail to get QE pathname");
        return AE_FAILURE;
    }
    if (SGX_SUCCESS != sgx_get_metadata(enclave_path, &metadata))
        return AE_FAILURE;
    *p_isvsvn = metadata.enclave_css.body.isv_svn;
    return AE_SUCCESS;
}

uint32_t CQEClass::get_quote(
    const sgx_report_t *p_report,
    sgx_qe_report_info_t *qe_report_info,
    uint8_t *p_quote,
    uint32_t quote_size)
{
    uint32_t ret = AE_SUCCESS;
    sgx_status_t status = SGX_SUCCESS;
    int retry = 0;
    sgx_quote_nonce_t nonce = qe_report_info->nonce;

    AESM_PROFILE_FUN;

    assert(m_enclave_id);
    status = ::get_quote(
        m_enclave_id,
        &ret,
        p_report,
        &nonce,
        &qe_report_info->app_enclave_target_info,
        &qe_report_info->qe_report,
        p_quote,
        quote_size);
    for(; status == SGX_ERROR_ENCLAVE_LOST && retry < AESM_RETRY_COUNT; retry++)
    {
        unload_enclave();
        // Reload an AE will not fail because of out of EPC, so AESM_AE_OUT_OF_EPC is not checked here
        if(AE_SUCCESS != load_enclave())
            return AE_FAILURE;
        status = ::get_quote(
            m_enclave_id,
            &ret,
            p_report,
            &nonce,
            &qe_report_info->app_enclave_target_info,
            &qe_report_info->qe_report,
            p_quote,
            quote_size);
    }
    if(status != SGX_SUCCESS)
        return AE_FAILURE;
    if(ret == QE_REVOKED_ERROR)
    {
        AESM_LOG_FATAL("%s", g_event_string_table[SGX_EVENT_EPID_REVOCATION]);
    }
    else if(ret == QE_SIGRL_ERROR)
    {
        AESM_LOG_FATAL("%s", g_event_string_table[SGX_EVENT_EPID20_SIGRL_INTEGRITY_ERROR]);
    }
    return ret;
}
