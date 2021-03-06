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

#ifndef _QE_CLASS_H_
#define _QE_CLASS_H_
#include "AEClass.h"
#include "aeerror.h"
#include "sgx_report.h"
#include "sgx_quote.h"
#include "ae_debug_flag.hh"

class CQEClass: public SingletonEnclave<CQEClass>
{
    friend class Singleton<CQEClass>;
    friend class SingletonEnclave<CQEClass>;
    static aesm_enclave_id_t get_enclave_fid(){return QE_ENCLAVE_FID;}
protected:
    CQEClass(){};
    ~CQEClass(){};
    virtual void before_enclave_load();
    virtual int get_debug_flag() { return AE_DEBUG_FLAG;}

public:
    virtual ae_error_t load_enclave();
    uint32_t get_qe_target(
        sgx_target_info_t *p_qe_target,
        sgx_isv_svn_t *p_isvsvn);
    uint32_t get_quote(
        const sgx_report_t *p_report,
        sgx_qe_report_info_t *qe_report_info,
        uint8_t *p_quote,
        uint32_t quote_size);
};
#endif
