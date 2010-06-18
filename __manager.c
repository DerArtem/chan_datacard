/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

static int manager_show_devices (struct mansession* s, const struct message* m)
{
	const char*	id = astman_get_header (m, "ActionID");
	char		idtext[256] = "";
	pvt_t*		pvt;
	size_t		count = 0;

	if (!ast_strlen_zero (id))
	{
		snprintf (idtext, sizeof (idtext), "ActionID: %s\r\n", id);
	}

	astman_send_listack (s, m, "Device status list will follow", "start");

	AST_RWLIST_RDLOCK (&devices);
	AST_RWLIST_TRAVERSE (&devices, pvt, entry)
	{
		ast_mutex_lock (&pvt->lock);
		astman_append (s, "Event: DatacardDeviceEntry\r\n%s", idtext);
		astman_append (s, "Device: %s\r\n", pvt->id);
		astman_append (s, "Group: %d\r\n", pvt->group);
		astman_append (s, "Connected: %s\r\n", pvt->connected ? "Yes" : "No");
		astman_append (s, "Initialized: %s\r\n", pvt->initialized ? "Yes" : "No");
		astman_append (s, "State: %s\r\n", (!pvt->connected) ? "None" : (pvt->outgoing || pvt->incoming) ? "Busy" : (pvt->outgoing_sms || pvt->incoming_sms) ? "SMS" : "Free");
		astman_append (s, "Voice: %s\r\n", (pvt->has_voice) ? "Yes" : "No");
		astman_append (s, "SMS: %s\r\n", (pvt->has_sms) ? "Yes" : "No");
		astman_append (s, "RSSI: %d\r\n", pvt->rssi);
		astman_append (s, "Mode: %d\r\n", pvt->linkmode);
		astman_append (s, "Submode: %d\r\n", pvt->linksubmode);
		astman_append (s, "ProviderName: %s\r\n", pvt->provider_name);
		astman_append (s, "Manufacturer: %s\r\n", pvt->manufacturer);
		astman_append (s, "Model: %s\r\n", pvt->model);
		astman_append (s, "Firmware: %s\r\n", pvt->firmware);
		astman_append (s, "IMEI: %s\r\n", pvt->imei);
		astman_append (s, "Number: %s\r\n", pvt->number);
		astman_append (s, "\r\n");
		ast_mutex_unlock (&pvt->lock);
		count++;
	}
	AST_RWLIST_UNLOCK (&devices);

	astman_append (s,
		"Event: DatacardShowDevicesComplete\r\n%s"
		"EventList: Complete\r\n"
		"ListItems: %lu\r\n"
		"\r\n",
		idtext, count
	);

	return 0;
}

static int manager_send_cusd (struct mansession* s, const struct message* m)
{
	const char*	device	= astman_get_header (m, "Device");
	const char*	cusd	= astman_get_header (m, "CUSD");
	const char*	id	= astman_get_header (m, "ActionID");

	char		idtext[256] = "";
	pvt_t*		pvt = NULL;
	char		buf[256];

	if (ast_strlen_zero (device))
	{
		astman_send_error (s, m, "Device not specified");
		return 0;
	}

	if (ast_strlen_zero (cusd))
	{
		astman_send_error (s, m, "CUSD not specified");
		return 0;
	}

	if (!ast_strlen_zero (id))
	{
		snprintf (idtext, sizeof (idtext), "ActionID: %s\r\n", id);
	}

	pvt = find_device (device);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected && pvt->initialized)
		{
			if (at_send_cusd (pvt, cusd) || at_fifo_queue_add (pvt, CMD_AT_CUSD, RES_OK))
			{
				ast_log (LOG_ERROR, "[%s] Error sending CUSD command\n", pvt->id);
			}
			else
			{
				astman_send_ack (s, m, "CUSD code send successful");
			}
		}
		else
		{
			snprintf (buf, sizeof (buf), "Device %s not connected / initialized.", device);
			astman_send_error (s, m, buf);
		}
		ast_mutex_unlock (&pvt->lock);
	}
	else
	{
		snprintf (buf, sizeof (buf), "Device %s not found.", device);
		astman_send_error (s, m, buf);
	}

	return 0;
}

static int manager_send_sms (struct mansession* s, const struct message* m)
{
	const char*	device	= astman_get_header (m, "Device");
	const char*	number	= astman_get_header (m, "Number");
	const char*	message	= astman_get_header (m, "Message");
	const char*	id	= astman_get_header (m, "ActionID");

	char		idtext[256] = "";
	pvt_t*		pvt = NULL;
	char*		msg;
	char		buf[256];

	if (ast_strlen_zero (device))
	{
		astman_send_error (s, m, "Device not specified");
		return 0;
	}

	if (ast_strlen_zero (number))
	{
		astman_send_error (s, m, "Number not specified");
		return 0;
	}

	if (ast_strlen_zero (message))
	{
		astman_send_error (s, m, "Message not specified");
		return 0;
	}

	if (!ast_strlen_zero (id))
	{
		snprintf (idtext, sizeof(idtext), "ActionID: %s\r\n", id);
	}

	pvt = find_device (device);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected && pvt->initialized)
		{
			if (pvt->has_sms)
			{
				msg = ast_strdup (message);
				if (at_send_cmgs (pvt, number) || at_fifo_queue_add_ptr (pvt, CMD_AT_CMGS, RES_SMS_PROMPT, msg))
				{
					ast_free (msg);
					ast_log (LOG_ERROR, "[%s] Error sending SMS message\n", pvt->id);
					astman_send_error (s, m, "SMS will not be sent");
				}
				else
				{
					astman_send_ack (s, m, "SMS send successful");
				}
			}
			else
			{
				snprintf (buf, sizeof (buf), "Device %s doesn't handle SMS -- SMS will not be sent", device);
				astman_send_error (s, m, buf);
			}
		}
		else
		{
			snprintf (buf, sizeof (buf), "Device %s not connected / initialized -- SMS will not be sent", device);
			astman_send_error (s, m, buf);
		}
		ast_mutex_unlock (&pvt->lock);
	}
	else
	{
		snprintf (buf, sizeof(buf), "Device %s not found -- SMS will not be sent", device);
		astman_send_error (s, m, buf);
	}

	return 0;
}

/*!
 * \brief Send a DatacardNewCUSD event to the manager
 * This function splits the message in multiple lines, so multi-line
 * CUSD messages can be send over the manager API.
 * \param pvt a pvt structure
 * \param message a null terminated buffer containing the message
 */

static void manager_event_new_cusd (pvt_t* pvt, char* message)
{
	struct ast_str* buf;
	char*	s = message;
	char*	sl;
	size_t	linecount = 0;

	buf = ast_str_create (256);

	while (sl = strsep (&s, "\r\n"))
	{
		if (*sl != '\0')
		{
			ast_str_append (&buf, 0, "MessageLine%lu: %s\r\n", linecount, sl);
			linecount++;
		}
	}

	manager_event (EVENT_FLAG_CALL, "DatacardNewCUSD",
		"Device: %s\r\n"
		"LineCount: %lu\r\n"
		"%s\r\n",
		pvt->id, linecount, ast_str_buffer (buf)
	);

	ast_free (buf);
}

/*!
 * \brief Send a DatacardNewSMS event to the manager
 * This function splits the message in multiple lines, so multi-line
 * SMS messages can be send over the manager API.
 * \param pvt a pvt structure
 * \param number a null terminated buffer containing the from number
 * \param message a null terminated buffer containing the message
 */

static void manager_event_new_sms (pvt_t* pvt, char* number, char* message)
{
	struct ast_str* buf;
	size_t	linecount = 0;
	char*	s = message;
	char*	sl;
	char*	ret;

	buf = ast_str_create (256);

	while (sl = strsep (&s, "\r\n"))
	{
		if (*sl != '\0')
		{
			ast_str_append (&buf, 0, "MessageLine%lu: %s\r\n", linecount, sl);
			linecount++;
		}
	}

	manager_event (EVENT_FLAG_CALL, "DatacardNewSMS",
		"Device: %s\r\n"
		"From: %s\r\n"
		"LineCount: %lu\r\n"
		"%s\r\n",
		pvt->id, number, linecount, ast_str_buffer (buf)
	);

	ast_free (buf);
}
