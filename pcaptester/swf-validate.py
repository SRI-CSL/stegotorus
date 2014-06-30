#!/usr/bin/env python
import sys
import struct

def validate_tags(data, wut=False):
    # 10 bit type, 6 bit length.  if all 6 bits are set, len is the
    # following 4 bytes.
    # first 2 bytes are byte swapped
    while len(data):

        if len(data) < 2:
            raise Exception("invalid swf: tagcode_and_length too short")

        tgc = data[:2]
        data = data[2:]

        tag_type = ((ord(tgc[0]) & 0b11000000) >> 6) + (ord(tgc[1]) << 2)
        tag_len  = ord(tgc[0]) & 0b00111111
        if tag_len == 0b111111:
            tag_len = struct.unpack('<I', data[:4])[0]
            data = data[4:]

        if tag_len > len(data):
            raise Exception("invalid swf: invalid tag len %d" % (tag_len))

        if tag_type > 100:
            raise Exception("invalid swf: invalid tag type %d" % (tag_type))
        
        if tag_type == 39:
            tag_data = data[:tag_len]
            validate_tags(tag_data[4:], True) # skip SpriteID and FrameCount

        data = data[tag_len:]

def do_swf(data):
    if len(data) < 9:
        return "invalid swf: too short (%d bytes)" % (len(data))

    if data[:3] == "FWS":       # currently not handled
        compressed = False
    elif data[:3] == "CWS":
        compressed = True
    else:
        return "invalid swf: header magic (%s)" % data[:3].encode('hex')

    data = data[8:]
    if compressed:
        try:
            data = data.decode('zlib')
        except:
            raise Exception("RATPAC: compressed swf did not decompress")

    #### RECT ####
    # how many bytes to skip for the RECT
    bits = (((ord(data[0]) & 0b11111000) >> 3) * 4) + 5
    align = bits % 8
    if align != 0:
        bits += 8 - align
    skip = bits / 8
    if len(data) < skip:
        raise Exception("not valid swf: invalid RECT")

    data = data[skip:]

    #### rate & count ####
    data = data[4:]

    validate_tags(data)

for i in sys.argv[1:]:
    try:
        do_swf(open(i, 'rb').read())
    except Exception as e:
        print i, "error: %s" % (repr(e))
