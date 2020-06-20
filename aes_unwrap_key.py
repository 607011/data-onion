# -*- coding: utf-8 -*-
# Copyright (c) 2017 Kurt Rose, https://github.com/kurtbrose/aes_keywrap

from Crypto.Cipher import AES
import struct

def aes_unwrap_key_and_iv(kek, wrapped):
  assert(len(wrapped) % 8 == 0)
  n = len(wrapped) // 8 - 1
  QUAD = struct.Struct('>Q')
  # NOTE: R[0] is never accessed, left in for consistency with RFC indices
  R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
  A = QUAD.unpack(wrapped[:8])[0]
  decrypt = AES.new(kek, AES.MODE_ECB).decrypt
  for j in range(5,-1,-1):
    for i in range(n, 0, -1):
      ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
      B = decrypt(ciphertext)
      A = QUAD.unpack(B[:8])[0]
      R[i] = B[8:]
  return b''.join(R[1:]), QUAD.pack(A)

def aes_unwrap_key(kek: bytes, wrapped: bytes, iv: bytes) -> ():
  (key, key_iv) = aes_unwrap_key_and_iv(kek, wrapped)
  if key_iv != iv:
    raise ValueError('Given IV and unwrapped IV not identical')
  return (key, key_iv)
