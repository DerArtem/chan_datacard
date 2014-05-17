/*
   Copyright (C) 2009 - 2010
   
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
   
   Dmitry Vagin <dmitry2004@yandex.ru>
*/

static ssize_t conv_encoding (const char* in, size_t in_len, char* out, size_t out_size, char* from, char* to)
{
	ICONV_CONST char*	in_ptr = (ICONV_CONST char*) in;
	size_t			in_bytesleft = in_len;
	char*			out_ptr = out;
	size_t			out_bytesleft = out_size - 1;
	iconv_t			cd = (iconv_t) -1;
	ssize_t			res;

	cd = iconv_open (to, from);

	if (cd == (iconv_t) -1)
	{
		return -2;
	}

	res = iconv (cd, &in_ptr, &in_bytesleft, &out_ptr, &out_bytesleft);

	if (res < 0)
	{
		return -3;
	}

	iconv_close (cd);

	*out_ptr = '\0';

	return (out_ptr - out);
}

static ssize_t conv_char_to_8bit_hexstr (const char* in, size_t in_len, char* out, size_t out_size)
{
	size_t i;
	size_t x;
	char buf[] = { 0x0, 0x0, 0x0 };

	if (out_size - 1 < in_len * 2)
	{
		return -1;
	}

	for (i = 0, x = 0; i < in_len; i++)
	{
		snprintf (buf, sizeof (buf), "%.2X", in[i]);
		memmove (out + x, buf, 2);
		x = x + 2;
	}

	out[x] = '\0';

	return x;
}

static ssize_t conv_char_to_7bit_hexstr (const char* in, size_t in_len, char* out, size_t out_size)
{
	size_t		i;
	size_t		x;
	size_t		s;
	unsigned char	c;
	unsigned char	b;
	char		buf[] = { 0x0, 0x0, 0x0 };

	x = (in_len - in_len / 8) * 2;

	if (out_size - 1 < x)
	{
		return -1;
	}

	in_len--;
	for (i = 0, x = 0, s = 0; i < in_len; i++)
	{
		if (s == 7)
		{
			s = 0;
			continue;
		}

		c = in[i] >> s;
		b = in[i + 1] << (7 - s);
		c = c | b;
		s++;

		snprintf (buf, sizeof (buf), "%.2X", c);

		memmove (out + x, buf, 2);
		x = x + 2;
	}

	c = in[i] >> s;
	snprintf (buf, sizeof(buf), "%.2X", c);
	memmove (out + x, buf, 2);
	x = x + 2;

	out[x] = '\0';

	return x;
}

static ssize_t conv_8bit_hexstr_to_char (const char* in, size_t in_len, char* out, size_t out_size)
{
	size_t i;
	size_t x;
	int hexval = 0;
	char buf[] = { 0x0, 0x0, 0x0 };

	in_len = in_len / 2;

	if (out_size - 1 < in_len)
	{
		return -1;
	}

	for (i = 0, x = 0; i < in_len; i++)
	{
		memmove (buf, in + i * 2, 2);
		if (sscanf (buf, "%x", &hexval) != 1)
		{
			return -1;
		}
		out[x] = hexval;
		x++;
	}

	out[x] = '\0';

	return x;
}

static ssize_t conv_7bit_hexstr_to_char (const char* in, size_t in_len, char* out, size_t out_size)
{
	size_t		i;
	size_t		x;
	size_t		s;
	int		hexval;
	unsigned char	c;
	unsigned char	b;
	char		buf[] = { 0x0, 0x0, 0x0 };

	in_len = in_len / 2;
	x = in_len + in_len / 7;

	if (out_size - 1 < x)
	{
		return -1;
	}

	for (i = 0, x = 0, s = 1, b = 0; i < in_len; i++)
	{
		memmove (buf, in + i * 2, 2);
		if (sscanf (buf, "%x", &hexval) != 1)
		{
			return -1;
		}

		c = ((unsigned char) hexval) << s;
		c = (c >> 1) | b;
		b = ((unsigned char) hexval) >> (8 - s);

		out[x] = c;
		x++; s++;

		if (s == 8)
		{
			out[x] = b;
			s = 1; b = 0;
			x++;
		}
	}

	out[x] = '\0';

	return x;
}

static ssize_t conv_utf8_to_ucs2_8bit_hexstr (const char* in, size_t in_len, char* out, size_t out_size)
{
	char	buf[out_size];
	ssize_t	res;

	if (out_size - 1 < in_len * 2)
	{
		return -1;
	}

	res = conv_encoding (in, in_len, buf, out_size, "UTF-8", "UCS-2BE");

	if (res < 0)
	{
		return res;
	}

	res = conv_char_to_8bit_hexstr (buf, res, out, out_size);

	return res;
}

static ssize_t conv_utf8_to_latin1_7bit_hexstr (const char* in, size_t in_len, char* out, size_t out_size)
{
	char	buf[out_size];
	ssize_t	res;

	if (out_size - 1 < in_len * 2)
	{
		return -1;
	}

	res = conv_encoding (in, in_len, buf, out_size, "UTF-8", "LATIN1");

	if (res < 0)
	{
		return res;
	}

	res = conv_char_to_7bit_hexstr (buf, res, out, out_size);

	return res;
}

static ssize_t conv_ucs2_8bit_hexstr_to_utf8 (const char* in, size_t in_len, char* out, size_t out_size)
{
	char	buf[out_size];
	ssize_t	res;

	if (out_size - 1 < in_len / 2)
	{
		return -1;
	}

	res = conv_8bit_hexstr_to_char (in, in_len, buf, out_size);

	if (res < 0)
	{
		return res;
	}

	res = conv_encoding (buf, res, out, out_size, "UCS-2BE", "UTF-8");

	return res;
}

static ssize_t conv_latin1_8bit_hexstr_to_utf8 (const char* in, size_t in_len, char* out, size_t out_size)
{
	char	buf[out_size];
	ssize_t	res;

	if (out_size - 1 < in_len / 2)
	{
		return -1;
	}

	res = conv_8bit_hexstr_to_char (in, in_len, buf, out_size);

	if (res < 0)
	{
		return res;
	}

	res = conv_encoding (in, in_len, out, out_size, "ISO-8859-1", "UTF-8");

	return res;
}

static ssize_t conv_latin1_7bit_hexstr_to_utf8 (const char* in, size_t in_len, char* out, size_t out_size)
{
	char	buf[out_size];
	ssize_t	res;

	if (out_size - 1 < in_len / 2)
	{
		return -1;
	}

	res = conv_7bit_hexstr_to_char (in, in_len, buf, out_size);

	if (res < 0)
	{
		return res;
	}

	res = conv_encoding (in, in_len, out, out_size, "ISO-8859-1", "UTF-8");

	return res;
}
