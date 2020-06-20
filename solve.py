#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Solver for Tom's Data Onion (https://www.tomdalling.com/toms-data-onion/)
Copyright © 2020 Oliver Lau <oliver@ersatzworld.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see https://www.gnu.org/licenses/.
'''

import sys
from lxml import html
import requests
import base64
import numpy as np
import re
import struct
from Crypto.Cipher import AES
import const
from aes_unwrap_key import aes_unwrap_key

const.ip_fields = ['v_ihl', 'tos', 'total_length', 'id', 'flags_fragment_offset', 'ttl', 'protocol', 'header_checksum', 'source_address', 'destination_address']
const.udp_fields = ['source_port', 'destination_port', 'length', 'checksum']
const.IPHEADER = struct.Struct('!BBHHHBBHII')
const.UDPHEADER = struct.Struct('!HHHH')
const.ONEBYTE = struct.Struct('B')

def get_payload_of(data: str) -> bytes:
  match = re.search(r'<~(.+)~>', data, flags=re.M | re.S)
  if match is None:
    raise ValueError('no payload found')
  a85 = match.groups()[0]
  return base64.a85decode(a85)

def peel(onion_filename=None):
  # get onion from webpage or file
  if onion_filename is not None:
    with open(onion_filename, mode='r') as f:
      layer0 = f.read()
  else:
    page = requests.get('https://www.tomdalling.com/toms-data-onion/')
    tree = html.fromstring(page.content)
    layer0 = tree.xpath('//pre/text()')[0]
  data = get_payload_of(layer0)

  # first layer
  layer1 = data.decode('utf-8')
  data = get_payload_of(layer1)
  data = np.frombuffer(data, dtype=np.uint8)

  xored = np.bitwise_xor(data, 0b01010101)
  shifted = np.right_shift(xored, 1)
  msb = np.left_shift(xored, 7)
  data = np.bitwise_or(shifted, msb)
 
  # second layer
  layer2 = data.tostring().decode('utf-8')
  data = get_payload_of(layer2)
  data = np.frombuffer(data, dtype=np.uint8)

  def popcount(b: np.uint8) -> np.uint8:
    b = b - ((b >> 1) & 0x55)
    b = (b & 0x33) + ((b >> 2) & 0x33)
    return (((b + (b >> 4)) & 0x0f) * 0x01)

  def is_parity_ok(b: np.uint8) -> np.uint8:
    return popcount(b) % 2 == 0

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

  # third layer
  layer3 = merged.tostring().decode('utf-8')
  data = get_payload_of(layer3)
  encrypted = np.frombuffer(data, dtype=np.uint8)

  # launch known plaintext attack
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

  # fourth layer
  layer4 = np.vectorize(lambda x: x if x < 128 else ord('?'))(decrypted).tostring().decode('ascii')
  # print(layer4)

  data = get_payload_of(layer4)

  def ones_complement_sum_uint16(buffer: bytes) -> int:
    assert(len(buffer) % 2 == 0)
    values = struct.unpack(f'!{len(buffer)//2}H', buffer)
    total = sum(values)
    carry = total >> 16
    return (total & 0xffff) + carry

  def ip_header_checksum_ok(ip_header: bytes) -> bool:
    assert(len(ip_header) == 20)
    checksum = ones_complement_sum_uint16(ip_header)
    return checksum == 0xffff

  def udp_checksum(udp_packet: bytes, ip_header: bytes) -> int:
    ip_src = ip_header_bytes[12:16]
    ip_dst = ip_header_bytes[16:20]
    ip_proto = ip_header_bytes[9:10]
    udp_length = ip_header_bytes[2:4]
    pseudo_header = ip_src + ip_dst + b'\x00' + ip_proto + udp_length
    udp_packet_padded = udp_packet if len(udp_packet) % 2 == 0 else udp_packet + b'\x00'
    assert(len(udp_packet_padded) % 2 == 0)
    checksum = ones_complement_sum_uint16(pseudo_header + udp_packet_padded)
    return checksum - 20

  def udp_checksum_ok(udp_packet: bytes, ip_header: bytes) -> bool:
    return udp_checksum(udp_packet, ip_header) == 0

  def parsed_ip_header(buffer: bytes) -> dict:
    ipv4_hdr = const.IPHEADER.unpack(buffer)
    return dict(zip(const.ip_fields, ipv4_hdr))

  def parsed_udp_header(buffer: bytes) -> dict:
    udp_hdr = const.UDPHEADER.unpack(buffer)
    return dict(zip(const.udp_fields, udp_hdr))

  const.required_src = 0x0a01010a  # 10.1.1.10
  const.required_dst = 0x0a0101c8  # 10.1.1.200
  const.required_dst_port = 42069
  layer5 = b''
  idx = 0
  while idx < len(data):
    (v_ihl,) = const.ONEBYTE.unpack(data[idx:idx+1])
    ihl = 4 * (v_ihl & 0x0f)
    assert(ihl == 20)
    ip_header_bytes = data[idx:idx+ihl]
    ip_header = parsed_ip_header(ip_header_bytes)
    udp_header = parsed_udp_header(data[idx+ihl:idx+ihl+8])
    udp_packet = data[idx+ihl:idx+ihl+udp_header['length']]
    udp_packet_data = udp_packet[8:]
    if ip_header_checksum_ok(ip_header_bytes) \
      and ip_header['source_address'] == const.required_src \
        and ip_header['destination_address'] == const.required_dst \
          and udp_header['destination_port'] == const.required_dst_port \
            and udp_checksum_ok(udp_packet, ip_header_bytes):
      layer5 += udp_packet_data
    idx += ip_header['total_length']
  
  # fifth layer
  layer5 = layer5.decode('utf-8')
  # print(layer5)

  data = get_payload_of(layer5)
  kek = data[0:32]
  iv_wrapped_key = data[32:40]
  wrapped_key = data[40:80]
  iv = data[80:96]
  encrypted = data[96:]
  (key, _) = aes_unwrap_key(kek, wrapped_key, iv_wrapped_key)
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  plaintext = cipher.decrypt(encrypted)

  # WOOT! :-)
  print(plaintext.decode('utf-8'))


if __name__ == '__main__':
  if len(sys.argv) == 2:
    peel(sys.argv[1])
  else:
    peel()
