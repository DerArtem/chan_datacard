/*
 * Copyright (C) 2009 - 2010 Artem Makhutov
 * Artem Makhutov <artem@makhutov.org>
 * http://www.makhutov.org
 *
 * This functions are used to convert hex encoded
 * UCS-2 to UTF-8 and vice versa.
 */

#include <stdio.h>
#include <string.h>
#include <iconv.h>
#include "char_conv.h"

size_t convert_string(char *in, size_t in_length, char *out, size_t out_length, char *from, char *to)
{
	int res;
	size_t inbytesleft = in_length;
	size_t outbytesleft = out_length;
	char *in_ptr = &in[0];
	char *out_ptr = &out[0];
	iconv_t cd;

	if (out_length-in_length<0) {
		return -1;
	}

	if ((cd = iconv_open(to, from)) == (iconv_t)(-1)) {
		return -2;
	}

	res = iconv(cd, &in_ptr, &inbytesleft, &out_ptr, &outbytesleft);
	if (res < 0) {
		return -3;
	}
	iconv_close(cd);

	out_ptr[0]='\0';

	return (out_length-outbytesleft);
}

size_t hexstr_to_ucs2char(char *in, size_t in_length, char *out, size_t out_length)
{
	size_t i = 0;
	size_t x = 0;
	int hexval = 0;
	char buf[] = "  ";

	if ((out_length*2)<in_length) return -1;

	for (i=0;i<in_length/2;i++) {
		buf[0] = in[(i*2)];
		buf[1] = in[(i*2)+1];
		if (sscanf(buf, "%x", &hexval) != 1) {
			return -1;
		}
		out[x] = hexval;
		x++;
	}

	x = (x - (x%2));
	return x;
}

size_t ucs2char_to_hexstr(char *in, size_t in_length, char *out, size_t out_length)
{
	size_t i = 0;
	size_t x = 0;
	char buf[] = "  ";

	if ((out_length*4)<in_length) return -1;

	for (i=0;i<in_length;i++) {
		snprintf(buf,sizeof(buf),"%X",in[i]);

		if (buf[1] == '\0') {
			buf[1] = buf[0];
			buf[0] = '0';
		}
		out[x] = buf[0];
		out[x+1] = buf[1];
		x=x+2;
	}

	out[x] = '\0';

	return x;
}

size_t hexstr_ucs2_to_utf8(char *in, size_t in_length, char *out, size_t out_length)
{
	char buf[out_length];
	size_t res;

	if ((out_length*2)<in_length) return -1;

	if ((res = hexstr_to_ucs2char(in, in_length, buf, out_length)) < 0) return res;
	res = convert_string(buf, res, out, out_length, "UCS-2BE", "UTF-8");
	return res;
}

size_t utf8_to_hexstr_ucs2(char *in, size_t in_length, char *out, size_t out_length)
{
	char buf[out_length];
	size_t res;

	if (out_length<in_length) return -1;

	if ((res = convert_string(in, in_length, buf, out_length, "UTF-8", "UCS-2BE")) < 0) return res;
	res = ucs2char_to_hexstr(buf, res, out, out_length);
	return res;
}
