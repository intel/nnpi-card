/********************************************
 * Copyright (C) 2019-2020 Intel Corporation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 ********************************************/


#include "ice_safe_func.h"

int ice_strlen_s(const char *dest, int dest_max)
{
	int count;

	if (dest == NULL)
		return -EINVAL;

	if (dest_max == 0)
		return -EINVAL;

	count = 0;
	while (*dest && dest_max) {
		count++;
		dest_max--;
		dest++;
	}

	return count;
}

int ice_memset_s(void *dest, size_t dest_limit, int c, size_t n)
{
	errno_t err = 0;

	if (dest == NULL) {
		err = -EINVAL;
		goto out;
	}
	if (n > dest_limit) {
		err = -E2BIG;
		goto out;
	}

	memset(dest, c, n);

out:
	return err;
}

bool ice_safe_memcpy(void *dest, size_t dest_size,
		const void *src, size_t num_bytes)
{
	int ret = 0;

	if (num_bytes == 0)
		return true;
	if (dest == NULL || src == NULL || dest_size == 0)
		return false;
	if (num_bytes > dest_size)
		return false;

	/* Banned aip used after all checks */
	memcpy(dest, src, num_bytes);

	if (dest_size > num_bytes) {
		ret = ice_memset_s(&((char *)dest)[num_bytes],
			dest_size - num_bytes, 0,
			dest_size - num_bytes);
		if (ret < 0)
			return false;
	}

	return true;
}

int ice_memcpy_s(void *dest, size_t dest_size,
		const void *src, size_t num_bytes)
{
	return ice_safe_memcpy(dest, dest_size,
			src, num_bytes) == true ? 0 : -EINVAL;
}

bool ice_safe_strncpy(char *dest, size_t dest_size,
		const char *src, size_t max_chars)
{
	int ret = 0;

	if (max_chars == 0)
		return false;

	if (dest == NULL || src == NULL || dest_size == 0)
		return false;

	if (max_chars > dest_size)
		return false;

	/* Banned aip used after all checks */
	strncpy(dest, src, max_chars);

	if (dest_size == max_chars) {
		dest[dest_size-1] = '\0';
	} else {
		ret = ice_memset_s(&dest[max_chars], dest_size - max_chars,
				0, dest_size - max_chars);
		if (ret < 0)
			return false;
	}
	return true;
}

int ice_strncpy_s(char *dest, size_t dest_size,
		const char *src, size_t max_chars)
{
	return ice_safe_strncpy(dest, dest_size,
			src, max_chars) == true ? 0 : -EINVAL;
}


bool ice_safe_strcat(char *dest, size_t max_dest_size, const char *src)
{
	size_t src_len = 0, dest_len = 0;
	char *dest_ctr = dest;
	const char *src_ctr = src;

	if (dest == NULL || src == NULL || max_dest_size == 0)
		return false;

	while (*dest_ctr != '\0') {
		dest_ctr++;
		dest_len++;
	}
	if (dest_len >= (max_dest_size - 1))
		return false;

	while (*src_ctr != '\0') {
		src_ctr++;
		src_len++;
	}
	if (dest_len + src_len > (max_dest_size - 1))
		return false;

	/* Banned aip used after all checks */
	strcat(dest, src);

	return true;

}

int ice_strcat_s(char *dest, size_t dest_size, const char *src)
{
	return ice_safe_strcat(dest, dest_size, src) == true ? 0 : -EINVAL;
}


uint32_t parse_fmt_str(const char *format, char format_id_list[],
		unsigned int max_fmt_cnt)
{
	unsigned int  numFormats = 0;
	unsigned int  index = 0;
	char len_mod = 0;

	while (index < MAX_STR_LENGTH && format[index] != '\0' &&
			numFormats < max_fmt_cnt) {
		if (format[index] == '%') {
			switch (format[++index]) {
			case '\0':
				continue;
			case '%':
				continue;
			case '+':
			case '-':
			case '#':
			case '0':
			case ' ':
				index++;
				break;
			}
			while (format[index] != '\0' &&
					format[index] >= '0' &&
					format[index] <= '9') {
				index++;
			}
			/* Check for an skip the optional precision */
			if (format[index] != '\0' && format[index] == '.') {
				index++;
				while (format[index] != '\0' &&
						format[index] >= '0' &&
						format[index] <= '9') {
					index++;
				}
			}
			/* Check for and skip the optional length modifiers */
			len_mod = ' ';
			switch (format[index]) {
			case 'h':
				if (format[++index] == 'h') {
					++index;
					/*also recognize the 'hh' modifier */
					len_mod = 'H';
					/* for char */
				} else {
					len_mod = 'h';
					/* for short */
				}
				break;
			case 'l':
				if (format[++index] == 'l') {
					++index;
					/*also recognize the 'll' modifier */
					len_mod = 'd';
					/* for long long */
				} else {
					len_mod = 'l';
					/* for long */
				}
				break;
			case 'L':
				len_mod = 'L'; break;
			case 'j':
			case 't':
			case 'z':
				index++;
				break;
			}

			/* Recognize and record the actual modifier */
			switch (format[index]) {
			case 'c':
				if (len_mod == 'l') {
					format_id_list[numFormats] = WCHAR_ID;
					/* store the format character */
				} else {
					 format_id_list[numFormats] = CHAR_ID;
				}
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 'd':
			case 'i':
			case 'u':
			case 'o':
			case 'X':
			case 'x':
				/* unsigned */
				if (len_mod == 'H') {
					format_id_list[numFormats] = CHAR_ID;
					/* store the format character */
				} else if (len_mod == 'l') {
					format_id_list[numFormats] = LONG_ID;
					/* store the format character */
				} else if (len_mod == 'h') {
					format_id_list[numFormats] = SHORT_ID;
					/* store the format character */
				} else{
					format_id_list[numFormats] = INT_ID;
				}
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 'A':
			case 'a':
			case 'E':
			case 'e':
			case 'F':
			case 'f':
			case 'G':
			case 'g':
				if (len_mod == 'L') {
					format_id_list[numFormats] = LDOUBLE_ID;
					/* store the format character */
				} else{
					format_id_list[numFormats] = DOUBLE_ID;
				}
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 'n':
				if (len_mod == 'H') {
					format_id_list[numFormats] = PCHAR_ID;
					/* store the format character */
				} else if (len_mod == 'l') {
					format_id_list[numFormats] = PLONG_ID;
					/* store the format character */
				} else if (len_mod == 'h') {
					format_id_list[numFormats] = PSHORT_ID;
					/* store the format character */
				} else {
					format_id_list[numFormats] = PINT_ID;
				}
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 'p':
				format_id_list[numFormats] = VOID_ID;
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 's':
				if (len_mod == 'l' || len_mod == 'L') {
					format_id_list[numFormats] = WSTRING_ID;
					/* store the format character */
				} else {
					format_id_list[numFormats] = STRING_ID;
				}
				numFormats++;
				index++;
				/* skip the format character */
				break;

			case 'm':
			/* Does not represent an argument in the call stack */
				 index++;
				/* skip the format character */
				continue;
			default:
			/*	puts("]"); */
				break;
			}
		} else {
			index++;
			/* move past this character */
		}
	}

	return numFormats;
}

uint32_t check_uint_format(const char format)
{
	uint32_t retval = 0;

	switch (format) {
	case UNSIGN_ID:
	case CHAR_ID:
	case SHORT_ID:
	case INT_ID:
		/* return 1 if success */
		retval = 1;
		break;
	}
	return retval;
}

uint32_t verify_integer_format(const char format)
{
	uint32_t  retval = 0;

	switch (format) {
	case CHAR_ID:
	case SHORT_ID:
	case INT_ID:
		/* return 1 if success */
		retval = 1;
		break;
	}
	return retval;
}


#ifdef RING3_VALIDATION
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

int ice_snprintf_s_ssss(char *dest, size_t dmax, const char *format,
	       const char *s1, const char *s2, const char *s3, const char *s4)
{
	char format_id_list[4];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 4);

	if (nfo != 4) {
		dest[0] = '\0';
		return -EINVAL;
	}
	for (i = 0; i < 3; i++) {

		if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}

	return snprintf(dest, dmax, format, s1, s2, s3, s4);
}
int ice_snprintf_s_s(char *dest, size_t dmax, const char *format,
	       const char *s)
{
	char format_id_list[1];
	int index = 0;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 1);

	if (nfo != 1) {
		dest[0] = '\0';
		return -EINVAL;
	}

	if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}

	return snprintf(dest, dmax, format, s);
}

int ice_snprintf_s_su(char *dest, size_t dmax, const char *format,
		const char *s, uint64_t a)
{
	char format_id_list[2];
	int index = 0;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 2);

	if (nfo != 2) {
		dest[0] = '\0';
		return -EINVAL;
	}

	if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	if (check_uint_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;


	return snprintf(dest, dmax, format, s, a);
}

int ice_snprintf_s_si(char *dest, size_t dmax, const char *format,
		const char *s, int a)
{
	char format_id_list[2];
	int index = 0;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 2);

	if (nfo != 2) {
		dest[0] = '\0';
		return -EINVAL;
	}

	if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	if (verify_integer_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;


	return snprintf(dest, dmax, format, s, a);
}

int ice_snprintf_s_u(char *dest, size_t dest_size, const char *format,
		uint64_t val1)
{
	char format_id_list[1];
	unsigned int index = 0;

	/* Determine the number of format options in the format string */
	unsigned int  nfo = parse_fmt_str(format, &format_id_list[0], 1);

	/* Check that there are not too many format options */
	if (nfo != 1) {
		dest[0] = '\0';
		return -EINVAL;
	}
	if (check_uint_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	return snprintf(dest, dest_size, format, val1);

}

int ice_snprintf_s_uu(char *dest, size_t dest_size, const char *format,
		uint64_t val1, uint64_t val2)
{
	char format_id_list[2];
	unsigned int index = 0;

	/* Determine the number of format options in the format string */
	unsigned int  nfo = parse_fmt_str(format, &format_id_list[0], 2);

	/* Check that there are not too many format options */
	if (nfo != 2) {
		dest[0] = '\0';
		return -EINVAL;
	}
	if (check_uint_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	if (check_uint_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;
	return snprintf(dest, dest_size, format, val1, val2);

}

int ice_snprintf_s_i(char *dest, size_t dest_size, const char *format,
		int val1)
{
	char format_id_list[1];
	int index = 0;

	/* Determine the number of format options in the format string */
	unsigned int  nfo = parse_fmt_str(format, &format_id_list[0], 1);

	/* Check that there are not too many format options */
	if (nfo != 1) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* Check that the format is for an integer type */
	if (verify_integer_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	return snprintf(dest, dest_size, format, val1);

}

int ice_snprintf_s_ii(char *dest, size_t dest_size, const char *format,
		int val1, int val2)
{
	char format_id_list[2];
	unsigned int index = 0;

	/* Determine the number of format options in the format string */
	unsigned int  nfo = parse_fmt_str(format, &format_id_list[0], 2);

	/* Check that there are not too many format options */
	if (nfo != 2) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* Check that the format is for an integer type */
	if (verify_integer_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;


	if (verify_integer_format(format_id_list[index]) == 0) {
		dest[0] = '\0';
		return -EINVAL;
	}
	index++;

	return snprintf(dest, dest_size, format, val1, val2);

}

int ice_snprintf_s_uuuuuuuu(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
		uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
	char format_id_list[8];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 8);

	if (nfo != 8) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 8; i++) {
		if (check_uint_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}


	return snprintf(dest, dmax, format,
			a1, a2, a3, a4, a5, a6, a7, a8);
}

int ice_snprintf_s_uuuuu(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
		uint64_t a5)
{
	char format_id_list[5];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 5);

	if (nfo != 5) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 5; i++) {
		if (check_uint_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}


	return snprintf(dest, dmax, format, a1, a2, a3, a4, a5);
}
int ice_snprintf_s_uuuss(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, uint64_t a3,
		const char *s1, const char *s2)
{
	char format_id_list[5];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 5);

	if (nfo != 5) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 3; i++) {
		if (check_uint_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}

	for (i = 0; i < 2; i++) {
		if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}

	return snprintf(dest, dmax, format, a1, a2, a3, s1, s2);
}

int ice_snprintf_s_iiiss(char *dest, size_t dmax, const char *format,
		int a1, int a2, int a3, const char *s1, const char *s2)
{
	char format_id_list[5];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 5);

	if (nfo != 5) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 3; i++) {
		if (verify_integer_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}

	for (i = 0; i < 2; i++) {
		if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}

	return snprintf(dest, dmax, format, a1, a2, a3, s1, s2);
}


int ice_snprintf_s_iisss(char *dest, size_t dmax, const char *format,
		int a1, int a2, const char *s1, const char *s2, const char *s3)
{
	char format_id_list[5];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 5);

	if (nfo != 5) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 2; i++) {
		if (verify_integer_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}
	for (i = 0; i < 3; i++) {
		if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}
	return snprintf(dest, dmax, format, a1, a2, s1, s2, s3);
}

int ice_snprintf_s_uusss(char *dest, size_t dmax, const char *format,
		uint64_t a1, uint64_t a2, const char *s1, const char *s2,
		const char *s3)
{
	char format_id_list[5];
	int index = 0;
	int i;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 5);

	if (nfo != 5) {
		dest[0] = '\0';
		return -EINVAL;
	}
	/* TODO: Check 5 patameters*/
	for (i = 0; i < 2; i++) {
		if (check_uint_format(format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}
	for (i = 0; i < 3; i++) {
		if (CHK_FORMAT(STRING_ID, format_id_list[index]) == 0) {
			dest[0] = '\0';
			return -EINVAL;
		}
		index++;
	}
	return snprintf(dest, dmax, format, a1, a2, s1, s2, s3);
}

inline int ice_sscanf_s_u8(const char *src, const char *format,
		uint8_t *dest)
{
	char format_id_list[1];
	int index = 0;
	int ret;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 1);

	if (dest == NULL || src == NULL)
		return -EINVAL;
	/* Check for 1 format */
	if (nfo != 1)
		return -EINVAL;

	if (check_uint_format(format_id_list[index]) == 0)
		return -EINVAL;

	/* Using Banned function after checking all the parameters */
	ret = sscanf(src, format, dest);
	return ret;
}

inline int ice_sscanf_s_u32(const char *src, const char *format,
		uint32_t *dest)
{
	char format_id_list[1];
	int index = 0;
	int ret;

	unsigned int nfo = parse_fmt_str(format, &format_id_list[0], 1);

	if (dest == NULL || src == NULL)
		return -EINVAL;
	/* Check for 1 format */
	if (nfo != 1)
		return -EINVAL;

	if (check_uint_format(format_id_list[index]) == 0)
		return -EINVAL;

	/* Using Banned function after checking all the parameters */
	ret = sscanf(src, format, dest);
	return ret;
}


#ifdef RING3_VALIDATION
#pragma GCC diagnostic warning "-Wformat-nonliteral"
#endif
