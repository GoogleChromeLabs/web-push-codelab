#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Yann GUIBET <yannguibet@gmail.com>.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from .openssl import OpenSSL


# For python3
def _equals_bytes(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _equals_str(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0


def equals(a, b):
    if isinstance(a, str):
        return _equals_str(a, b)
    else:
        return _equals_bytes(a, b)


def hmac_sha256(k, m):
    """
    Compute the key and the message with HMAC SHA5256
    """
    key = OpenSSL.malloc(k, len(k))
    d = OpenSSL.malloc(m, len(m))
    md = OpenSSL.malloc(0, 32)
    i = OpenSSL.pointer(OpenSSL.c_int(0))
    OpenSSL.HMAC(OpenSSL.EVP_sha256(), key, len(k), d, len(m), md, i)
    return md.raw


def hmac_sha512(k, m):
    """
    Compute the key and the message with HMAC SHA512
    """
    key = OpenSSL.malloc(k, len(k))
    d = OpenSSL.malloc(m, len(m))
    md = OpenSSL.malloc(0, 64)
    i = OpenSSL.pointer(OpenSSL.c_int(0))
    OpenSSL.HMAC(OpenSSL.EVP_sha512(), key, len(k), d, len(m), md, i)
    return md.raw


def pbkdf2(password, salt=None, i=10000, keylen=64):
    if salt is None:
        salt = OpenSSL.rand(8)
    p_password = OpenSSL.malloc(password, len(password))
    p_salt = OpenSSL.malloc(salt, len(salt))
    output = OpenSSL.malloc(0, keylen)
    OpenSSL.PKCS5_PBKDF2_HMAC(p_password, len(password), p_salt,
                              len(p_salt), i, OpenSSL.EVP_sha256(),
                              keylen, output)
    return salt, output.raw
