#!/usr/bin/env python
import sys
import struct
import re

def do_js(data):
    matches = {
        'copyright' : re.compile(
            "(Copyright [12](?!\d{3})[0-9a-f]{3})[\s\-]", re.DOTALL),
        'new'       : re.compile(
            "((?:return\s|=)\s*n[0-9a-df]w\s+\w+)", re.DOTALL),
        'reserved'  : re.compile(
            "(All Rights (R[a-df0-9]s[a-f0-9]rv[a-f0-9][a-f0-9]"+
            "|R[a-f0-9]s[a-df0-9]rv[a-f0-9][a-f0-9]"+
            "|R[a-f0-9]s[a-f0-9]rv[a-df0-9][a-f0-9]"+
            "|R[a-f0-9]s[a-f0-9]rv[a-f0-9][a-ce-f0-9]))", re.DOTALL)
        }
    
    for i in matches:
        m = matches[i].search(data)
        if m:
            return "invalid %s: %s" % (i, m.groups(0)[0])
        
        return None 


for i in sys.argv[1:]:
    try:
        do_js(open(i, 'rb').read())
    except Exception as e:
        print i, "error: %s" % (repr(e))
