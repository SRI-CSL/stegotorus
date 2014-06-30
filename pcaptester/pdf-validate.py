#!/usr/bin/env python
import os, re, struct, sys

if len(sys.argv) != 2:
    print "Usage: %s filename.pdf" % (sys.argv[0])
    sys.exit(0)

filename = sys.argv[1]
filp = open(filename, 'r')

badfilter_match = re.compile("/Filter[ \t/].*stream([^\r\n]+)", re.IGNORECASE)
flate_match = re.compile("/Filter[ \t]*/FlateDecode.*stream", re.IGNORECASE)
content_match = re.compile("Content-Type:", re.IGNORECASE)
pdftype_match = re.compile("^%PDF-([0-9.]+)", re.IGNORECASE)
encrypt_match = re.compile("/Encrypt[ \t]+[0-9]+[ \t]+[0-9]+[ \t]*R", re.IGNORECASE)

dingdingding = False
encrypted = False
found = False
lineno = 0
badfilter_insert = False
while 1:
    lines = filp.readlines(8*1024)
    if not lines: break
    for line in lines:
        m = badfilter_match.search(line)
        if m:
            badfilter_insert = True
            print "Stegotarus arithmetic filter error found at line", lineno
        if found:
            # First line after the FlateDecode filter line
            (cinfo, finfo) = struct.unpack('BB', line[:2])
            cwin = cinfo >> 4
            cm = cinfo & 0x0f
            flevel = finfo >> 6
            fdict = (finfo >> 5) & 0x1
            fcheck = finfo & 0x1f

            if cm != 8:
                print "line %d win size %xh CM: %xh - NOT Z_DEFLATED" % (lineno, cwin, cm)
                dingdingding = True
            else:
                pass
            found = False
        else:
            m = flate_match.search(line)
            if m:
                matched_line = line
                found = True
            m = content_match.match(line)
            if m:
                content = line
                which_req = lineno
            m = pdftype_match.match(line)
            if m:
                pdftype = m.groups(1)
                which_req = lineno
            m = encrypt_match.search(line)
            if m:
                encrypted = True
        lineno = lineno + 1
filp.close()

if badfilter_insert:
    bf = "Stegotaurus identified"
# else:
#    bf = "Stegotaurus not found"
# print "%s: Newline method: %s" %(filename, bf)

if dingdingding == False:
        deflate = "stegotaurus not found"
elif encrypted:
        deflate = "encrypted PDF requires more code to determine stegotaurus"
else:
    print "stegotaurus found"


# "%s: Deflate validation method: %s" %(filename, deflate)
