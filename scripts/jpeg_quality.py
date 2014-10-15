# change jpeg quality (default: 30; target: 70)

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

from PIL import Image


target_jpeg_quality = 30

def request(context, flow):
    if flow.request.headers["content-type"]:
        if flow.request.headers["content-type"] == ["image/jpeg"]:
            print "DISRUPT (request): jpeg"
            s = StringIO(flow.request.content)
            img = Image.open(s)
            print "img info: ", img.format, img.size, img.mode
            s2 = StringIO()
            img.save(s2, "JPEG", quality=target_jpeg_quality)
            # img.save(s2, "JPEG")
            flow.request.content = s2.getvalue()
        else:
            print "PASS: request content-type eq ", flow.request.headers["content-type"]

    else:
        print "PASS: cannot find content-type in flow.request.headers"


def response(context, flow):
    if flow.response.headers["content-type"]:
        if flow.response.headers["content-type"] == ["image/jpeg"]:
            print "DISRUPT (response): jpeg"
            s = StringIO(flow.response.content)
            img = Image.open(s)
            print "img info: ", img.format, img.size, img.mode
            s2 = StringIO()
            img.save(s2, "JPEG", quality=target_jpeg_quality)
            # img.save(s2, "JPEG")
            flow.response.content = s2.getvalue()
        else:
            print "PASS: response content-type eq ", flow.response.headers["content-type"]

    else:
        print "PASS: cannot find content-type in flow.response.headers"


