/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <resolv.h>
#include <cutils/list.h>
#include <cutils/sockets.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_auth.h"
#include "fdevent.h"
#include "mincrypt/rsa.h"

#define TRACE_TAG TRACE_AUTH


struct adb_public_key {
    struct listnode node;
    RSAPublicKey key;
};

static fdevent listener_fde;
static int framework_fd = -1;

void __attribute__((weak)) adb_auth_reload_keys(void)
{

}

int __attribute__((weak)) adb_auth_generate_token(void *token, size_t token_size)
{
    FILE *f;
    int ret;

    f = fopen("/dev/urandom", "re");
    if (!f)
        return 0;

    ret = fread(token, token_size, 1, f);

    fclose(f);
    return ret * token_size;
}

int __attribute__((weak)) adb_auth_verify(void *token, void *sig, int siglen)
{
        return 0;
}

void __attribute__((weak)) adb_auth_confirm_key(unsigned char *key, size_t len, atransport *t)
{

}

void __attribute__((weak)) adb_auth_init(void)
{

}
