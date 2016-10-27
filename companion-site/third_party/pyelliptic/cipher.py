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


class Cipher:
    """
    Symmetric encryption

        import pyelliptic
        iv = pyelliptic.Cipher.gen_IV('aes-256-cfb')
        ctx = pyelliptic.Cipher("secretkey", iv, 1, ciphername='aes-256-cfb')
        ciphertext = ctx.update('test1')
        ciphertext += ctx.update('test2')
        ciphertext += ctx.final()

        ctx2 = pyelliptic.Cipher("secretkey", iv, 0, ciphername='aes-256-cfb')
        print ctx2.ciphering(ciphertext)
    """
    def __init__(self, key, iv, do, ciphername='aes-256-cbc'):
        """
        do == 1 => Encrypt; do == 0 => Decrypt
        """
        self.cipher = OpenSSL.get_cipher(ciphername)
        self.ctx = OpenSSL.EVP_CIPHER_CTX_new()
        if do == 1 or do == 0:
            k = OpenSSL.malloc(key, len(key))
            IV = OpenSSL.malloc(iv, len(iv))
            OpenSSL.EVP_CipherInit_ex(
                self.ctx, self.cipher.get_pointer(), 0, k, IV, do)
        else:
            raise Exception("RTFM ...")

    @staticmethod
    def get_all_cipher():
        """
        static method, returns all ciphers available
        """
        return OpenSSL.cipher_algo.keys()

    @staticmethod
    def get_blocksize(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return cipher.get_blocksize()

    @staticmethod
    def gen_IV(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return OpenSSL.rand(cipher.get_blocksize())

    def update(self, input):
        i = OpenSSL.c_int(0)
        buffer = OpenSSL.malloc(b"", len(input) + self.cipher.get_blocksize())
        inp = OpenSSL.malloc(input, len(input))
        if OpenSSL.EVP_CipherUpdate(self.ctx, OpenSSL.byref(buffer),
                                    OpenSSL.byref(i), inp, len(input)) == 0:
            raise Exception("[OpenSSL] EVP_CipherUpdate FAIL ...")
        return buffer.raw[0:i.value]

    def final(self):
        i = OpenSSL.c_int(0)
        buffer = OpenSSL.malloc(b"", self.cipher.get_blocksize())
        if (OpenSSL.EVP_CipherFinal_ex(self.ctx, OpenSSL.byref(buffer),
                                       OpenSSL.byref(i))) == 0:
            raise Exception("[OpenSSL] EVP_CipherFinal_ex FAIL ...")
        return buffer.raw[0:i.value]

    def ciphering(self, input):
        """
        Do update and final in one method
        """
        buff = self.update(input)
        return buff + self.final()

    def __del__(self):
        OpenSSL.EVP_CIPHER_CTX_cleanup(self.ctx)
        OpenSSL.EVP_CIPHER_CTX_free(self.ctx)
