/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

/*!
 * \brief Write to data socket
 * \param pvt -- pvt structure
 * \param buf -- buffer to write (null terminated)
 *
 * This function will write characters from buf. The buffer must be null terminated.
 *
 * \retval -1 error
 * \retval  0 success
 */

static inline int at_write (pvt_t* pvt, char* buf)
{
	return at_write_full (pvt, buf, strlen (buf));
}


/*!
 * \brief Write to data socket
 * \param pvt -- pvt structure
 * \param buf -- buffer to write
 * \param count -- number of bytes to write
 *
 * This function will write count characters from buf. It will always write
 * count chars unless it encounters an error.
 *
 * \retval -1 error
 * \retval  0 success
 */

static int at_write_full (pvt_t* pvt, char* buf, size_t count)
{
	char*	p = buf;
	ssize_t	out_count;

	ast_debug (5, "[%s] [%.*s]\n", pvt->id, count, buf);

	while (count > 0)
	{
		if ((out_count = write (pvt->data_socket, p, count)) == -1)
		{
			ast_debug (1, "[%s] write() error: %d\n", pvt->id, errno);
			return -1;
		}

		count -= out_count;
		p += out_count;
	}

	return 0;
}

/*!
 * \brief Send the AT command
 * \param pvt -- pvt structure
 */

static inline int at_send_at (pvt_t* pvt)
{
	return at_write_full (pvt, "AT\r", 3);
}

/*!
 * \brief Send ATA command
 * \param pvt -- pvt structure
 */

static inline int at_send_ata (pvt_t* pvt)
{
	return at_write_full (pvt, "ATA\r", 4);
}

/*!
 * \brief Send the AT+CGMI command
 * \param pvt -- pvt structure
 */

static inline int at_send_cgmi (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CGMI\r", 8);
}

/*!
 * \brief Send the AT+CGMM command
 * \param pvt -- pvt structure
 */

static inline int at_send_cgmm (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CGMM\r", 8);
}

/*!
 * \brief Send the AT+CGMR command
 * \param pvt -- pvt structure
 */

static inline int at_send_cgmr (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CGMR\r", 8);
}

/*!
 * \brief Send the AT+CGSN command
 * \param pvt -- pvt structure
 */

static inline int at_send_cgsn (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CGSN\r", 8);
}

/*!
 * \brief Send AT+CHUP command
 * \param pvt -- pvt structure
 */

static inline int at_send_chup (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CHUP\r", 8);
}

/*!
 * \brief Enable or disable calling line identification
 * \param pvt -- pvt structure
 * \param status -- enable or disable calling line identification (should be 1 or 0)
 */

static inline int at_send_clip (pvt_t* pvt, int status)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CLIP=%d\r", status ? 1 : 0);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send AT+CLVL command
 * \param pvt -- pvt structure
 * \param volume -- level to send
 */

static inline int at_send_clvl (pvt_t* pvt, int level)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CLVL=%d\r", level);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Delete an SMS message
 * \param pvt -- pvt structure
 * \param index -- the location of the requested message
 */

static inline int at_send_cmgd (pvt_t* pvt, int index)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CMGD=%d\r", index);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Set the SMS mode
 * \param pvt -- pvt structure
 * \param mode -- the sms mode (0 = PDU, 1 = Text)
 */

static inline int at_send_cmgf (pvt_t* pvt, int mode)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CMGF=%d\r", mode);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Read an SMS message
 * \param pvt -- pvt structure
 * \param index -- the location of the requested message
 */

static inline int at_send_cmgr (pvt_t* pvt, int index)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CMGR=%d\r", index);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Start sending an SMS message
 * \param pvt -- pvt structure
 * \param number -- the destination of the message
 */

static inline int at_send_cmgs (pvt_t* pvt, const char* number)	// !!!!!!!!!
{
	ssize_t	res;
	char*	p;

	memcpy (pvt->send_buf, "AT+CMGS=\"", 9);
	p = pvt->send_buf + 9;

//	if (pvt->use_ucs2_encoding)
	{
		res = utf8_to_hexstr_ucs2 (number, strlen (number), p, sizeof (pvt->send_buf) - 9 - 3);
		if (res <= 0)
		{
			ast_log (LOG_ERROR, "[%s] Error converting SMS number to UCS-2): %s\n", pvt->id, number);
			return -1;
		}
		p += res;
		memcpy (p, "\"\r", 3);
	}
//	else
	{
//		snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CMGS=\"%s\"\r", number);
	}

	return at_write (pvt, pvt->send_buf);
}

/*!
 * \brief Setup SMS new message indication
 * \param pvt -- pvt structure
 */

static inline int at_send_cnmi (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CNMI=2,1,0,0,0\r", 18);
}

/*!
 * \brief Send the AT+CNUM command
 * \param pvt -- pvt structure
 */

static inline int at_send_cnum (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CNUM\r", 8);
}

/*!
 * \brief Send the AT+COPS? command
 * \param pvt -- pvt structure
 */

static inline int at_send_cops (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+COPS?\r", 9);
}

/*!
 * \brief Send the AT+COPS= command
 * \param pvt -- pvt structure
 */

static inline int at_send_cops_init (pvt_t* pvt, int mode, int format)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+COPS=%d,%d\r", mode, format);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send AT+CPIN? to ask the datacard if a pin code is required
 * \param pvt -- pvt structure
 */

static inline int at_send_cpin_test (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CPIN?\r", 9);
}

/*!
 * \brief Set storage location for incoming SMS
 * \param pvt -- pvt structure
 */

static inline int at_send_cpms (pvt_t* pvt)
{
//	return at_write_full (pvt, "AT+CPMS=\"SM\",\"SM\",\"SM\"\r", 23);
	return at_write_full (pvt, "AT+CPMS=\"ME\",\"ME\",\"ME\"\r", 23);
}

/*!
 * \brief Send the AT+CREG? command
 * \param pvt -- pvt structure
 */

static inline int at_send_creg (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CREG?\r", 9);
}

/*!
 * \brief Send the AT+CREG=n command
 * \param pvt -- pvt structure
 * \param level -- verbose level of CREG
 */

static inline int at_send_creg_init (pvt_t* pvt, int level)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CREG=%d\r", level);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send AT+CSCS.
 * \param pvt -- pvt structure
 * \param encoding -- encoding for SMS text mode
 */

static inline int at_send_cscs (pvt_t* pvt, const char* encoding)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CSCS=\"%s\"\r", encoding);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send AT+CSQ.
 * \param pvt -- pvt structure
 */

static inline int at_send_csq (pvt_t* pvt)
{
	return at_write_full (pvt, "AT+CSQ\r", 7);
}

/*!
 * \brief Manage Supplementary Service Notification.
 * \param pvt -- pvt structure
 * \param cssi the value to send (0 = disabled, 1 = enabled)
 * \param cssu the value to send (0 = disabled, 1 = enabled)
 */

static inline int at_send_cssn (pvt_t* pvt, int cssi, int cssu)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT+CSSN=%d,%d\r", cssi, cssu);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send AT+CUSD.
 * \param pvt -- pvt structure
 * \param code the CUSD code to send
 */

static inline int at_send_cusd (pvt_t* pvt, const char* code)	// !!!!!!!!!!
{
	ssize_t	res;
	char*	p;

	memcpy (pvt->send_buf, "AT+CUSD=1,\"", 11);
	p = pvt->send_buf + 11;

	res = char_to_hexstr_7bit (code, strlen (code), p, sizeof (pvt->send_buf) - 11 - 6);
	if (res <= 0)
	{
		ast_log (LOG_ERROR, "[%s] Error converting CUSD code to PDU): %s\n", pvt->id, code);
		return -1;
	}

	p += res;
	memcpy (p, "\",15\r", 6);

	return at_write (pvt, pvt->send_buf);
}

/*!
 * \brief Check device for audio capabilities
 * \param pvt -- pvt structure
 */

static inline int at_send_cvoice_test (pvt_t* pvt)
{
	return at_write_full (pvt, "AT^CVOICE?\r", 11);
}

/*!
 * \brief Send ATD command
 * \param pvt -- pvt structure
 * \param number -- the number to dial
 */

static inline int at_send_atd (pvt_t* pvt, const char* number)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "ATD%s;\r", number);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Enable transmitting of audio to the debug port (tty)
 * \param pvt -- pvt structure
 */

static inline int at_send_ddsetex (pvt_t* pvt)
{
	return at_write_full (pvt, "AT^DDSETEX=2\r", 13);
}

/*!
 * \brief Send a DTMF command
 * \param pvt -- pvt structure
 * \param digit -- the dtmf digit to send
 * \return the result of at_write() or -1 on an invalid digit being sent
 */

static inline int at_send_dtmf (pvt_t* pvt, char digit)
{
	switch (digit)
	{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '*':
		case '#':
			pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT^DTMF=1,%c\r", digit);
			return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));

		default:
			return -1;
	}
}

/*!
 * \brief Send the ATE0 command
 * \param pvt -- pvt structure
 */

static inline int at_send_ate0 (pvt_t* pvt)
{
	return at_write_full (pvt, "ATE0\r", 5);
}

/*!
 * \brief Send the text of an SMS message
 * \param pvt -- pvt structure
 * \param message -- the text of the message
 */

static inline int at_send_sms_text (pvt_t* pvt, const char* message)	// !!!!!!!!!
{
	ssize_t	res;
	char	ucs2_message[4096];
	char	cmd[sizeof (ucs2_message) + 162];

	if (pvt->use_ucs2_encoding)
	{
		res = utf8_to_hexstr_ucs2 (message, strlen (message), ucs2_message, sizeof (ucs2_message));
		if (res <= 0)
		{
			ast_log (LOG_ERROR, "[%s] Error converting SMS to UCS-2): %s\n", pvt->id, message);
			return -1;
		}
		snprintf (cmd, sizeof (cmd), "%.160s\x1a", ucs2_message);
	}
	else
	{
		snprintf (cmd, sizeof (cmd), "%.160s\x1a", message);
	}

	return at_write (pvt, cmd);
}

/*!
 * \brief Set the U2DIAG mode
 * \param pvt -- pvt structure
 * \param mode -- the U2DIAG mode (0 = Only modem functions)
 */

static inline int at_send_u2diag (pvt_t* pvt, int mode)
{
	pvt->send_size = snprintf (pvt->send_buf, sizeof (pvt->send_buf), "AT^U2DIAG=%d\r", mode);
	return at_write_full (pvt, pvt->send_buf, MIN (pvt->send_size, sizeof (pvt->send_buf) - 1));
}

/*!
 * \brief Send the ATZ command
 * \param pvt -- pvt structure
 */

static inline int at_send_atz (pvt_t* pvt)
{
	return at_write_full (pvt, "ATZ\r", 4);
}
