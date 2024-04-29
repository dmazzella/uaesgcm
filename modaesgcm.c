/*
 * This file is part of the Micro Python project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Damiano Mazzella
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "py/runtime.h"
#include "py/binary.h"
#include "py/objstr.h"
#include "py/objint.h"

#include "AesGCM.h"

static int mp_random(void *rng_state, byte *output, size_t len)
{
    size_t use_len;
    int rnd;

    if (rng_state != NULL)
    {
        rng_state = NULL;
    }

    while (len > 0)
    {
        use_len = len;
        if (use_len > sizeof(int))
            use_len = sizeof(int);
        rnd = rand();
        memcpy(output, &rnd, use_len);
        output += use_len;
        len -= use_len;
    }

    return 0;
}

static const mp_obj_type_t ciphers_aesgcm_type;

typedef struct _mp_ciphers_aesgcm_t
{
    mp_obj_base_t base;
    vstr_t *key;
} mp_ciphers_aesgcm_t;

static mp_obj_t aesgcm_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args)
{
    mp_arg_check_num(n_args, n_kw, 1, 1, false);
    mp_obj_t key = args[0];

    mp_buffer_info_t bufinfo_key;
    mp_get_buffer_raise(key, &bufinfo_key, MP_BUFFER_READ);

    mp_ciphers_aesgcm_t *AESGCM = m_new_obj(mp_ciphers_aesgcm_t);
    AESGCM->base.type = &ciphers_aesgcm_type;
    AESGCM->key = vstr_new(bufinfo_key.len);
    vstr_add_strn(AESGCM->key, bufinfo_key.buf, bufinfo_key.len);

    return MP_OBJ_FROM_PTR(AESGCM);
}

static mp_obj_t aesgcm_generate_key(mp_obj_t bit_length)
{
#if !defined(__thumb2__) && !defined(__thumb__) && !defined(__arm__)
    time_t t;
    srand((unsigned)time(&t));
#endif
    if (!mp_obj_is_int(bit_length))
    {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected bit_length int"));
    }

    mp_int_t nbit = mp_obj_get_int(bit_length);
    if (nbit != 128 && nbit != 192 && nbit != 256)
    {
        mp_raise_ValueError(MP_ERROR_TEXT("bit_length must be 128, 192 OR 256"));
    }

    vstr_t vstr_key;
    vstr_init_len(&vstr_key, nbit / 8);
    mp_random(NULL, (byte *)vstr_key.buf, vstr_key.len);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_key.buf, vstr_key.len);
    vstr_clear(&vstr_key);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_1(mod_aesgcm_generate_key_obj, aesgcm_generate_key);
static MP_DEFINE_CONST_STATICMETHOD_OBJ(mod_static_aesgcm_generate_key_obj, MP_ROM_PTR(&mod_aesgcm_generate_key_obj));

static mp_obj_t aesgcm_encrypt(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;

    mp_ciphers_aesgcm_t *AESGCM = MP_OBJ_TO_PTR(args[0]);

    mp_buffer_info_t bufinfo_nonce;
    mp_get_buffer_raise(args[1], &bufinfo_nonce, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(args[2], &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_associated_data;
    bool use_associated_data = mp_get_buffer(args[3], &bufinfo_associated_data, MP_BUFFER_READ);

    vstr_t vstr_tag;
    vstr_init_len(&vstr_tag, 16);

    vstr_t vstr_output;
    vstr_init_len(&vstr_output, bufinfo_data.len);

    aes_gcm_encrypt((byte *)vstr_output.buf, (byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)AESGCM->key->buf, AESGCM->key->len, (byte *)bufinfo_nonce.buf, bufinfo_nonce.len, (byte *)bufinfo_associated_data.buf, (use_associated_data ? bufinfo_associated_data.len : 0), (byte *)vstr_tag.buf, vstr_tag.len);

    vstr_add_strn(&vstr_output, vstr_tag.buf, vstr_tag.len);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf, vstr_output.len);
    vstr_clear(&vstr_tag);
    vstr_clear(&vstr_output);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aesgcm_encrypt_obj, 4, 4, aesgcm_encrypt);

static mp_obj_t aesgcm_decrypt(size_t n_args, const mp_obj_t *args)
{
    (void)n_args;

    mp_ciphers_aesgcm_t *AESGCM = MP_OBJ_TO_PTR(args[0]);
    (void)AESGCM;

    mp_buffer_info_t bufinfo_nonce;
    mp_get_buffer_raise(args[1], &bufinfo_nonce, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_data;
    mp_get_buffer_raise(args[2], &bufinfo_data, MP_BUFFER_READ);

    mp_buffer_info_t bufinfo_associated_data;
    bool use_associated_data = mp_get_buffer(args[3], &bufinfo_associated_data, MP_BUFFER_READ);
    (void)use_associated_data;

    vstr_t vstr_tag;
    vstr_init_len(&vstr_tag, 16);

    vstr_t vstr_output;
    vstr_init_len(&vstr_output, bufinfo_data.len - vstr_tag.len);

    aes_gcm_decrypt((byte *)vstr_output.buf, (byte *)bufinfo_data.buf, bufinfo_data.len, (byte *)AESGCM->key->buf, AESGCM->key->len, (byte *)bufinfo_nonce.buf, bufinfo_nonce.len, (byte *)bufinfo_associated_data.buf, (use_associated_data ? bufinfo_associated_data.len : 0), (byte *)vstr_tag.buf, vstr_tag.len);

    mp_obj_t oo = mp_obj_new_bytes((const byte *)vstr_output.buf, vstr_output.len);
    vstr_clear(&vstr_tag);
    vstr_clear(&vstr_output);
    return oo;
}

static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_aesgcm_decrypt_obj, 4, 4, aesgcm_decrypt);

static const mp_rom_map_elem_t aesgcm_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_generate_key), MP_ROM_PTR(&mod_static_aesgcm_generate_key_obj)},
    {MP_ROM_QSTR(MP_QSTR_encrypt), MP_ROM_PTR(&mod_aesgcm_encrypt_obj)},
    {MP_ROM_QSTR(MP_QSTR_decrypt), MP_ROM_PTR(&mod_aesgcm_decrypt_obj)},
};

static MP_DEFINE_CONST_DICT(aesgcm_locals_dict, aesgcm_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_aesgcm_type,
    MP_QSTR_AESGCM,
    MP_TYPE_FLAG_NONE,
    make_new, aesgcm_make_new,
    locals_dict, &aesgcm_locals_dict);

static const mp_rom_map_elem_t ciphers_locals_dict_table[] = {
    {MP_ROM_QSTR(MP_QSTR_AESGCM), MP_ROM_PTR(&ciphers_aesgcm_type)},
};

static MP_DEFINE_CONST_DICT(ciphers_locals_dict, ciphers_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    ciphers_type,
    MP_QSTR_ciphers,
    MP_TYPE_FLAG_NONE,
    locals_dict, &ciphers_locals_dict);

static const mp_rom_map_elem_t mp_module_uaesgcm_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR__aesgcm)},
    {MP_ROM_QSTR(MP_QSTR_ciphers), MP_ROM_PTR((mp_obj_type_t *)&ciphers_type)},
};

static MP_DEFINE_CONST_DICT(mp_module_uaesgcm_globals, mp_module_uaesgcm_globals_table);

const mp_obj_module_t mp_module_uaesgcm = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_uaesgcm_globals,
};

// Register the module to make it available in Python
MP_REGISTER_MODULE(MP_QSTR__aesgcm, mp_module_uaesgcm);
