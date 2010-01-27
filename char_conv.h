/*
 * Copyright (C) 2009 - 2010 Artem Makhutov
 * Artem Makhutov <artem@makhutov.org>
 * http://www.makhutov.org
 */

size_t convert_string(char *in, size_t in_length, char *out, size_t out_length, char *from, char *to);
size_t hexstr_to_ucs2char(char *in, size_t in_length, char *out, size_t out_length);
size_t ucs2char_to_hexstr(char *in, size_t in_length, char *out, size_t out_length);
size_t hexstr_ucs2_to_utf8(char *in, size_t in_length, char *out, size_t out_length);
size_t utf8_to_hexstr_ucs2(char *in, size_t in_length, char *out, size_t out_length);
