#ifndef HTTP_ZLIB_HPP
#define HTTP_ZLIB_HPP

namespace Http
{
    #if defined(HTTP_PLATFORM_WINDOWS)
    #define ZLIB_VERSION "1.3.1"
    #else
    #define ZLIB_VERSION "1.3.2"
    #endif

    typedef unsigned char Byte; /* 8 bits */
    typedef Byte Bytef;
    typedef unsigned int uInt;   /* 16 bits or more */
    typedef unsigned long uLong; /* 32 bits or more */
    typedef void const *voidpc;
    typedef void *voidpf;
    typedef void *voidp;
    typedef voidpf (*alloc_func)(voidpf opaque, uInt items, uInt size);
    typedef void (*free_func)(voidpf opaque, voidpf address);

    typedef struct z_stream_s
    {
        Bytef *next_in;               /* next input byte */
        uInt avail_in;                /* number of bytes available at next_in */
        uLong total_in;               /* total number of input bytes read so far */
        Bytef *next_out;              /* next output byte will go here */
        uInt avail_out;               /* remaining free space at next_out */
        uLong total_out;              /* total number of bytes output so far */
        const char *msg;              /* last error message, NULL if no error */
        struct internal_state *state; /* not visible by applications */
        alloc_func zalloc;            /* used to allocate the internal state */
        free_func zfree;              /* used to free the internal state */
        voidpf opaque;                /* private data object passed to zalloc and zfree */
        int data_type;                /* best guess about the data type: binary or text
                                      for deflate, or the decoding state for inflate */
        uLong adler;                  /* Adler-32 or CRC-32 value of the uncompressed data */
        uLong reserved;               /* reserved for future use */
    } z_stream;

    typedef z_stream *z_streamp;

    int inflateInit2_(z_streamp strm, int windowBits, const char *version, int stream_size);
    int inflate(z_streamp strm, int flush);
    int inflateEnd(z_streamp strm);

#define inflateInit2(strm, windowBits)                \
    inflateInit2_((strm), (windowBits), ZLIB_VERSION, \
                  (int)sizeof(z_stream))

    bool zlib_load_library(void);
    void zlib_unload_library(void);
}

#endif