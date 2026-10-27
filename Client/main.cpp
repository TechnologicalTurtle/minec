/* zpipe.c: example of proper use of zlib's inflate() and deflate()
   Not copyrighted -- provided to the public domain
   Version 1.5  11 February 2026  Mark Adler */

/* Version history:
   1.0  30 Oct 2004  First version
   1.1   8 Nov 2004  Add void casting for unused return values
                     Use switch statement for inflate() return values
   1.2   9 Nov 2004  Add assertions to document zlib guarantees
   1.3   6 Apr 2005  Remove incorrect assertion in inf()
   1.4  11 Dec 2005  Add hack to avoid MSDOS end-of-line conversions
                     Avoid some compiler warnings for input and output buffers
   1.5  11 Feb 2026  Use underscores for Windows POSIX names
 */

#include <vector>
#include <iostream>

#include "zlib.h"

#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
   def() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_STREAM_ERROR if an invalid compression
   level is supplied, Z_VERSION_ERROR if the version of zlib.h and the
   version of the library linked do not match, or Z_ERRNO if there is
   an error reading or writing the files.
int def(FILE *source, FILE *dest, int level)
{
    int err, flush;
    unsigned out_len;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    // init strm structure
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    err = deflateInit(&strm, level);
    if (err != Z_OK) return err;

    //compress until end of file
    do {
        // load
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)deflateEnd(&strm);
            return Z_ERRNO;
        }
        flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
        strm.next_in = in;

        // run deflate() on input until output buffer not full, finish
           compression if all of source has been read in //
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;

            err = deflate(&strm, flush);    // no bad return value //
            assert(err != Z_STREAM_ERROR);  // state not clobbered //

            out_len = CHUNK - strm.avail_out;
            if (fwrite(out, 1, out_len, dest) != out_len || ferror(dest)) {
                deflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        assert(strm.avail_in == 0);     // all input will be used //

        // done when last data in file processed //
    } while (flush != Z_FINISH);
    assert(err == Z_STREAM_END);        // stream will be complete //

    //clean up and return //
    deflateEnd(&strm);
    return Z_OK;
}

// Decompress from file source to file dest until stream ends or EOF.
   inf() returns Z_OK on success, Z_MEM_ERROR if memory could not be
   allocated for processing, Z_DATA_ERROR if the deflate data is
   invalid or incomplete, Z_VERSION_ERROR if the version of zlib.h and
   the version of the library linked do not match, or Z_ERRNO if there
   is an error reading or writing the files. //
int inf(FILE *source, FILE *dest)
{
    int err;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    // init strm
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    err = inflateInit(&strm);
    if (err != Z_OK)
        return err;

    /* decompress until deflate stream ends or end of file /
    do {
        // load
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full /
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;

            err = inflate(&strm, Z_NO_FLUSH);
            assert(err != Z_STREAM_ERROR);  /* state not clobbered /

            switch (err) {
            case Z_NEED_DICT:
                err = Z_DATA_ERROR;     /* and fall through /
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return err;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done /
    } while (err != Z_STREAM_END);

    /* clean up and return /
    inflateEnd(&strm);
    return err == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

/* report a zlib or i/o error /
void zerr(int ret)
{
    fputs("zpipe: ", stderr);
    switch (ret) {
    case Z_ERRNO:
        if (ferror(stdin))
            fputs("error reading stdin\n", stderr);
        if (ferror(stdout))
            fputs("error writing stdout\n", stderr);
        break;
    case Z_STREAM_ERROR:
        fputs("invalid compression level\n", stderr);
        break;
    case Z_DATA_ERROR:
        fputs("invalid or incomplete deflate data\n", stderr);
        break;
    case Z_MEM_ERROR:
        fputs("out of memory\n", stderr);
        break;
    case Z_VERSION_ERROR:
        fputs("zlib version mismatch!\n", stderr);
    }
}*/

#include <cstdint>

/* compress or decompress from stdin to stdout */
int main()
{
    std::vector<uint8_t> input = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    std::vector<uint8_t> compressed;
    std::vector<unsigned char> got;
    {

        int err;
        int flush = Z_FINISH;
        unsigned out_len;
        z_stream strm;

        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);

        size_t at = 0;

        strm.avail_in = input.size();
        strm.next_in = &input[0];

        do
        {
            compressed.resize(CHUNK);

            strm.avail_out = CHUNK;
            strm.next_out = &compressed[at];
            at += CHUNK;

            err = deflate(&strm, flush);

            out_len = CHUNK - strm.avail_out;
            deflateEnd(&strm);
        } while (strm.avail_out == 0);
        compressed.resize(compressed.size() - strm.avail_out);
    }

    {
        int err;
        unsigned out_len;
        z_stream strm;
        unsigned char input[CHUNK];
        unsigned char output[CHUNK];

        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.avail_in = 0;
        strm.next_in = Z_NULL;
        err = inflateInit(&strm);

        strm.avail_in = compressed.size();
        for (int i = 0; i < compressed.size(); ++i) {
            input[i] = compressed[i];
        }
        strm.next_in = input;

        strm.avail_out = CHUNK;
        strm.next_out = output;

        err = inflate(&strm, Z_NO_FLUSH);
        out_len = CHUNK - strm.avail_out;

        got.reserve(out_len);
        for (int i = 0; i < out_len; ++i) {
            got.push_back(output[i]);
        }
    }
    for (const auto a : got)
        std::cout << a;
    std::cout << std::endl;
}