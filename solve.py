#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import numpy as np
import re
import struct
from Crypto.Cipher import AES

import const

const.ip_fields = ['v_ihl', 'tos', 'total_length', 'id', 'flags_fragment_offset', 'ttl', 'protocol', 'header_checksum', 'source_address', 'destination_address']
const.udp_fields = ['source_port', 'destination_port', 'length', 'checksum']
const.IPHEADER = struct.Struct('!BBHHHBBHII')
const.UDPHEADER = struct.Struct('!HHHH')
const.ONEBYTE = struct.Struct('B')

def get_payload_of(data: str) -> bytes:
  match = re.search(r'<~(.+)~>', data, flags=re.M | re.S)
  if match is None:
    raise 'no payload found'
  a85 = match.groups()[0]
  return base64.a85decode(a85)

def popcount(b: np.uint8) -> np.uint8:
  b = b - ((b >> 1) & 0x55)
  b = (b & 0x33) + ((b >> 2) & 0x33)
  return (((b + (b >> 4)) & 0x0f) * 0x01)

def is_parity_ok(b: np.uint8) -> np.uint8:
  return popcount(b) % 2 == 0

def to_bit_sequence(b: [np.uint8]) -> str:
  return ' '.join([bin(x)[2:].zfill(8) for x in b])

def main():
  f = open('solutions/layer0.txt', mode='r')
  layer0 = f.read()
  f.close()

  data = get_payload_of(layer0)
  layer1 = data.decode('utf-8')

  data = get_payload_of(layer1)
  data = np.frombuffer(data, dtype=np.uint8)

  xored = np.bitwise_xor(data, 0b01010101)
  shifted = np.right_shift(xored, 1)
  msb = np.left_shift(xored, 7)
  data = np.bitwise_or(shifted, msb)
 
  layer2 = data.tostring().decode('utf-8')
  data = get_payload_of(layer2)
  data = np.frombuffer(data, dtype=np.uint8)

  filtered = data[is_parity_ok(data)]
  merged = np.empty(0, dtype=np.uint8)
  for i in range(0, len(filtered), 8):
    d = filtered[i:i+8]
    b = np.zeros(7, dtype=np.uint8)
    b[0] = (d[0] & 0b11111110) << 0 | ((d[1] & 0b10000000) >> 7)
    b[1] = (d[1] & 0b01111110) << 1 | ((d[2] & 0b11000000) >> 6)
    b[2] = (d[2] & 0b00111110) << 2 | ((d[3] & 0b11100000) >> 5)
    b[3] = (d[3] & 0b00011110) << 3 | ((d[4] & 0b11110000) >> 4)
    b[4] = (d[4] & 0b00001110) << 4 | ((d[5] & 0b11111000) >> 3)
    b[5] = (d[5] & 0b00000110) << 5 | ((d[6] & 0b11111100) >> 2)
    b[6] = (d[6] & 0b00000010) << 6 | ((d[7] & 0b11111110) >> 1)
    merged = np.append(merged, b)

  layer3 = merged.tostring().decode('utf-8')
  data = get_payload_of(layer3)
  encrypted = np.frombuffer(data, dtype=np.uint8)

  plaintext_start = np.frombuffer(b'==[ Layer 4/5: ', dtype=np.uint8)
  plaintext_end = np.frombuffer(b'~>\n', dtype=np.uint8)

  key_fragment_start = np.bitwise_xor(plaintext_start, encrypted[0:len(plaintext_start)])
  key_fragment_end = np.bitwise_xor(plaintext_end, encrypted[-len(plaintext_end):])

  nulls = np.frombuffer(b'\x00' * (32 - len(key_fragment_start) - len(key_fragment_end)), dtype=np.uint8)
  key = np.append(key_fragment_start, nulls)
  key = np.append(key, key_fragment_end)
  assert(len(key) == 32)

  decrypted = np.empty(0, dtype=np.uint8)
  for i in range(0, len(encrypted), len(key)):
    chunk = np.bitwise_xor(encrypted[i:i+len(key)], key)
    decrypted = np.append(decrypted, chunk)

  # layer4 = np.vectorize(lambda x: x if x < 128 else ord('?'))(decrypted).tostring().decode('ascii')
  # print(layer4)

  # layer4 reveals that bytes 47 to 60 probably are 'equal' characters.
  key_trial2 = np.bitwise_xor(encrypted[47:60], np.frombuffer(b'=============', dtype=np.uint8))
  key = np.append(key_fragment_start, key_trial2)
  key = np.append(key, np.frombuffer(b'\x00', dtype=np.uint8))
  key = np.append(key, key_fragment_end)
  assert(len(key) == 32)

  decrypted = np.empty(0, dtype=np.uint8)
  for i in range(0, len(encrypted), len(key)):
    chunk = np.bitwise_xor(encrypted[i:i+len(key)], key)
    decrypted = np.append(decrypted, chunk)

  # layer4 = np.vectorize(lambda x: x if x < 128 else ord('_'))(decrypted).tostring().decode('ascii')
  # print(layer4)

  # layer4 reveals the probable cleartext of the first 32 bytes
  key = np.bitwise_xor(encrypted[0:32], np.frombuffer(b'==[ Layer 4/5: Network Traffic ]', dtype=np.uint8))
  assert(len(key) == 32)

  decrypted = np.empty(0, dtype=np.uint8)
  for i in range(0, len(encrypted), len(key)):
    chunk = np.bitwise_xor(encrypted[i:i+len(key)], key)
    decrypted = np.append(decrypted, chunk)

  layer4 = np.vectorize(lambda x: x if x < 128 else ord('?'))(decrypted).tostring().decode('ascii')
  # print(layer4)

  data = get_payload_of(layer4)

  def ones_complement_sum_uint16(buffer: bytes) -> int:
    assert(len(buffer) % 2 == 0)
    values = struct.unpack(f'!{len(buffer)//2}H', buffer)
    total = sum(values)
    carry = (total & 0xffff0000) >> 16
    return (total & 0xffff) + carry

  def ip_header_checksum_ok(ip_header: bytes) -> bool:
    assert(len(ip_header) == 20)
    checksum = ones_complement_sum_uint16(ip_header)
    return checksum == 0xffff

  def udp_checksum(udp_packet: bytes, ip_src: bytes, ip_dst: bytes, ip_proto: bytes, udp_length: bytes) -> int:
    assert(len(ip_src) == 4)
    assert(len(ip_dst) == 4)
    assert(len(ip_proto) == 1 and ip_proto == b'\x11')
    assert(len(udp_length) == 2)
    pseudo_header = ip_src + ip_dst + b'\x00' + ip_proto + udp_length
    udp_packet_padded = udp_packet if len(udp_packet) % 2 == 0 else udp_packet + b'\x00'
    assert(len(udp_packet_padded) % 2 == 0)
    buffer = pseudo_header + udp_packet_padded
    checksum = ones_complement_sum_uint16(buffer)
    return checksum - 20

  def udp_checksum_ok(udp_packet: bytes, ip_src: bytes, ip_dst: bytes, ip_proto: bytes, udp_length: bytes) -> bool:
    return udp_checksum(udp_packet, ip_src, ip_dst, ip_proto, udp_length) == 0

  def parsed_ip_header(buffer: bytes) -> dict:
    ipv4_hdr = const.IPHEADER.unpack(buffer)
    return dict(zip(const.ip_fields, ipv4_hdr))

  def parsed_udp_header(buffer: bytes) -> dict:
    udp_hdr = const.UDPHEADER.unpack(buffer)
    return dict(zip(const.udp_fields, udp_hdr))

  required_src = 0x0a01010a  # 10.1.1.10
  required_dst = 0x0a0101c8  # 10.1.1.200
  required_dst_port = 42069
  layer5 = b''
  idx = 0
  while idx < len(data):
    (v_ihl,) = const.ONEBYTE.unpack(data[idx:idx+1])
    ihl = 4 * (v_ihl & 0x0f)
    assert(ihl == 20)
    ip_header_bytes = data[idx:idx+ihl]
    assert(len(ip_header_bytes) == 20)
    ip_header = parsed_ip_header(ip_header_bytes)
    udp_header = parsed_udp_header(data[idx+ihl:idx+ihl+8])
    udp_packet = data[idx+ihl:idx+ihl+udp_header['length']]
    udp_packet_data = udp_packet[8:]
    if ip_header_checksum_ok(ip_header_bytes) \
      and ip_header['source_address'] == required_src \
        and ip_header['destination_address'] == required_dst \
          and udp_header['destination_port'] == required_dst_port \
            and udp_checksum_ok(udp_packet, ip_header_bytes[12:16], ip_header_bytes[16:20], ip_header_bytes[9:10], ip_header_bytes[2:4]):
      layer5 += udp_packet_data
    idx += ip_header['total_length']
  
  layer5 = layer5.decode('utf-8')
  # print(layer5)

  data = get_payload_of(layer5)
  kek = data[0:32]
  iv_wrapped_key = data[32:40]
  wrapped_key = data[40:80]
  iv = data[80:96]
  encrypted = data[96:]

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
      raise ValueError('IV and key IV not identical')
    return (key, key_iv)

  (key, _) = aes_unwrap_key(kek, wrapped_key, iv_wrapped_key)
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  plaintext = cipher.decrypt(encrypted)
  print(plaintext.decode('utf-8'))  # WOOT! :-)


if __name__ == '__main__':
  main()
