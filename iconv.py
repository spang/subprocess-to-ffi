""" Reimplementation of the "iconv" Python C extension module from PyPI.

Unlike the existing Python extension module, we use cffi to write as little C
code as possible, and also do the conversion in a more portable manner.

The existing C extension module interprets Python's internal Py_UNICODE
representation and the iconv 'unicodelittle' codec as identical, which is
brittle and unportable and, depending on how Python was compiled, just plain
wrong. (You can introspect compile-time options using the `sysconfig` module,
but even with that it's difficult to get right all the time.)

We use UTF-8 as our intermediate representation since it is memory efficient
and probably doesn't take more bytes to represent a given string than the
input charset, which makes it reasonably easy to guess buffer sizes to use with
the iconv C API. We may wish to think more about the optimal intermediate
charset in terms of performance and memory efficiency later.

(More on Python's unicode representation here:
http://stackoverflow.com/questions/22149/unicode-vs-utf-8-confusion-in-python-django
)
"""
from cffi import FFI

ffi = FFI()

ffi.cdef("""
       typedef struct { ...; } iconv_t;
       iconv_t iconv_open(const char *tocode, const char *fromcode);
       size_t iconv(iconv_t cd,
		    char **inbuf, size_t *inbytesleft,
		    char **outbuf, size_t *outbytesleft);
       int iconv_close(iconv_t cd);
       #define E2BIG ...
       #define EINVAL ...
       #define EILSEQ ...
       void perror(const char *s);
        """)
C = ffi.verify("""
        #include <stdio.h>
        #include <errno.h>
        #include <iconv.h>
        """)

# from iconv(3) - perror's messages are too generic to be useful for us
error_messages = {
        C.E2BIG: "There is not sufficient room at *outbuf.",
        C.EILSEQ: "An invalid multibyte sequence has been encountered in the input.",
        C.EINVAL: "An incomplete multibyte sequence has been encountered in the input."
        }

class Iconv(object):
    def __init__(self, charset):
        self.charset = charset
        self.unicode_charset = unicode_charset = 'utf-8'
        self.unicode_width = 4  # max bytes per char
        # cd == "conversion descriptor" in the language of iconv's API
        # TODO: needs to throw ValueError when initialization fails
        self.encode_cd = C.iconv_open(charset, unicode_charset)
        assert self.encode_cd is not None
        self.decode_cd = C.iconv_open(unicode_charset, charset)
        assert self.decode_cd is not None

    def _reset_encoder(self):
        self._reset_cd(self.encode_cd)

    def _reset_decoder(self):
        self._reset_cd(self.decode_cd)

    def _reset_cd(self, cd):
        C.iconv(cd, ffi.NULL, ffi.NULL, ffi.NULL, ffi.NULL)

    def iconv(self, cd, msg_bytes, errors='strict'):
        # can't do &inbuf in cffi, need to explicitly create, fill pointer
        inbuf = ffi.new("char **")
        inbuf_text = ffi.new("char[]", msg_bytes)
        # *inbuf in cffi (works in C too but atypical)
        inbuf[0] = inbuf_text
        # give the output buffer some extra bytes compared to the input buffer
        # in case the input charset is more efficient for this string than
        # utf-8
        outbuf_size = len(msg_bytes) * 2
        outbuf = ffi.new("char **")
        outbuf_text = ffi.new("char []", outbuf_size)
        outbuf[0] = outbuf_text
        inbytesleft = ffi.new("size_t *")
        inbytesleft[0] = ffi.sizeof(inbuf_text)
        outbytesleft = ffi.new("size_t *")
        outbytesleft[0] = outbuf_size

        nconv = ffi.cast('int',
                C.iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft))

        self._check_errors(int(nconv))

        data_size = outbuf_size - outbytesleft[0]

        return outbuf_text, data_size

    def encode(self, msg, errors='strict'):
        """ Encode msg to `self.charset` from Python unicode. """

        assert isinstance(msg, unicode), "Unicode object required for encode"
        self._reset_encoder()

        msg_bytes = msg.encode('utf-8')

        outbuf_text, data_size = self.iconv(self.encode_cd, msg_bytes)

        return ffi.string(outbuf_text, data_size)

    def _check_errors(self, ret):
        assert isinstance(ret, int)

        if ret == -1:
            if ffi.errno in error_messages:
                errmsg = error_messages[ffi.errno]
            else:
                errmsg = C.perror("decode")
            raise Exception(errmsg)

    def decode(self, msg, errors='strict'):
        """ Decode msg from `self.charset` to Python unicode.

        We do the conversion by first using iconv to convert the message to
        UTF-8 bytes and then converting to a unicode object in Python.
        """
        assert not isinstance(msg, unicode), "Can only decode encoded bytes"
        self._reset_decoder()

        outbuf_text, data_size = self.iconv(self.decode_cd, msg)

        buf = ffi.buffer(outbuf_text, data_size)
        return unicode(buf, encoding=self.unicode_charset)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        C.iconv_close(self.encode_cd)
        C.iconv_close(self.decode_cd)

# TODO: handle "Bad file descriptor" error that happens when you pass in a
# bad charset.

# Way less C code == way less opportunity for C bugs. cffi is probably better
# tested than your code.

if __name__ == '__main__':
    # XXX UTF-16 and UTF-32 throw EINVAL, maybe something about byte order?
    # text = u"The quick brown fox".encode('utf-16')
    text = file('zhtext-iso2022-cn.txt').read()
    with Iconv('iso-2022-cn') as iconv:
    # with Iconv('UTF-16LE') as iconv:
        decoded = iconv.decode(text)
        print "decoded:", decoded
        encoded = iconv.encode(decoded)
        print "encoded:", encoded
