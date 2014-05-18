/*
   Copyright (C) 2009 - 2010
   
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
   
   Dmitry Vagin <dmitry2004@yandex.ru>
*/

static struct ast_channel* channel_new (pvt_t* pvt, int state, const char* cid_num, const char* dnid, const struct ast_channel* requestor)
{
	struct ast_channel* chan;

	pvt->answered = 0;

	ast_dsp_digitreset (pvt->dsp);

	chan = ast_channel_alloc (1, state, cid_num, pvt->id, NULL, dnid, pvt->context, requestor ? ast_channel_linkedid (requestor): NULL, 0, "Datacard/%s-%d", pvt->id, (int) ast_random () & 0xffff);

	if (chan)
	{
		ast_channel_tech_pvt_set (chan, pvt);
		ast_channel_tech_set (chan, &channel_tech);
		ast_format_set (ast_channel_readformat (chan), AST_FORMAT_SLINEAR, 0);
		ast_format_set (ast_channel_writeformat (chan), AST_FORMAT_SLINEAR, 0);
		ast_format_cap_add (ast_channel_nativeformats (chan), ast_channel_readformat (chan));

		if (state == AST_STATE_RING)
		{
			ast_channel_rings_set (chan, 1);
			pbx_builtin_setvar_helper (chan, "DATACARD",	pvt->id);
			pbx_builtin_setvar_helper (chan, "PROVIDER",	pvt->provider_name);
			pbx_builtin_setvar_helper (chan, "IMEI",	pvt->imei);
			pbx_builtin_setvar_helper (chan, "IMSI",	pvt->imsi);

			if (pvt->vars)
			{
				struct ast_variable*	var = NULL;
				char			varbuf[1024];

				for (var = pvt->vars; var; var = var->next)
				{
					pbx_builtin_setvar_helper (chan, var->name, ast_get_encoded_str (var->value, varbuf, sizeof (varbuf)));
				}
			}
		}

		if (!ast_strlen_zero (pvt->language))
		{
			ast_channel_language_set (chan, pvt->language);
		}

		ast_jb_configure (chan, &jbconf_global);

		if (pvt->audio_fd != -1)
		{
			ast_channel_set_fd (chan, 0, pvt->audio_fd);

			if ((pvt->a_timer = ast_timer_open ()))
			{
				ast_channel_set_fd (chan, 1, ast_timer_fd (pvt->a_timer));
				rb_init (&pvt->a_write_rb, pvt->a_write_buf, sizeof (pvt->a_write_buf));
			}
		}

		pvt->owner = chan;

		ast_module_ref (ast_module_info->self);

		return chan;
	}

	return NULL;
}

static struct ast_channel* channel_request (attribute_unused const char* type, struct ast_format_cap* cap, const struct ast_channel* requestor, const char* data, int* cause)
{
	char*			dest_dev = NULL;
	char*			dest_num = NULL;
	struct ast_channel*	channel = NULL;
	pvt_t*			pvt = NULL;
	int			group;
	size_t			i;
	size_t			j;
	size_t			c;
	size_t			last_used;

	if (!data)
	{
		ast_log (LOG_WARNING, "Channel requested with no data\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;
		return NULL;
	}

	if (!ast_format_cap_iscompatible (cap, &chan_datacard_format))
	{
		char buf[255];
		ast_log (LOG_WARNING, "Asked to get a channel of unsupported format '%s'\n", ast_getformatname_multiple (buf, sizeof (buf), cap));
		*cause = AST_CAUSE_FACILITY_NOT_IMPLEMENTED;
		return NULL;
	}

	dest_dev = ast_strdupa (data);

	dest_num = strchr (dest_dev, '/');
	if (!dest_num)
	{
		ast_log (LOG_WARNING, "Can't determine destination\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;
		return NULL;
	}

	*dest_num = '\0'; dest_num++;

	if (*dest_num == '\0')
	{
		ast_log (LOG_WARNING, "Empty destination\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;
		return NULL;
	}


	/* Find requested device and make sure it's connected and initialized. */

	AST_RWLIST_RDLOCK (&devices);

	if (((dest_dev[0] == 'g') || (dest_dev[0] == 'G')) && ((dest_dev[1] >= '0') && (dest_dev[1] <= '9')))
	{
		errno = 0;
		group = (int) strtol (&dest_dev[1], (char**) NULL, 10);
		if (errno != EINVAL)
		{
			AST_RWLIST_TRAVERSE (&devices, pvt, entry)
			{
				ast_mutex_lock (&pvt->lock);
				if (pvt->group == group && pvt->connected && pvt->initialized && pvt->has_voice && pvt->gsm_registered && !pvt->incoming && !pvt->outgoing && !pvt->owner)
				{
					break;
				}
				ast_mutex_unlock (&pvt->lock);
			}
		}
	}
	else if (((dest_dev[0] == 'r') || (dest_dev[0] == 'R')) && ((dest_dev[1] >= '0') && (dest_dev[1] <= '9')))
	{
		errno = 0;
		group = (int) strtol (&dest_dev[1], (char**) NULL, 10);
		if (errno != EINVAL)
		{
			ast_mutex_lock (&round_robin_mtx);

			/* Generate a list of all availible devices */
			j = sizeof (round_robin) / sizeof (round_robin[0]);
			c = 0; last_used = 0;
			AST_RWLIST_TRAVERSE (&devices, pvt, entry)
			{
				ast_mutex_lock (&pvt->lock);
				if (pvt->group == group)
				{
					round_robin[c] = pvt;
					if (pvt->group_last_used == 1)
					{
						pvt->group_last_used = 0;
						last_used = c;
					}

					c++;

					if (c == j)
					{
						ast_mutex_unlock (&pvt->lock);
						break;
					}
				}
				ast_mutex_unlock (&pvt->lock);
			}

			/* Search for a availible device starting at the last used device */
			for (i = 0, j = last_used + 1; i < c; i++, j++)
			{
				if (j == c)
				{
					j = 0;
				}

				pvt = round_robin[j];

				ast_mutex_lock (&pvt->lock);
				if (pvt->connected && pvt->initialized && pvt->has_voice && pvt->gsm_registered && !pvt->incoming && !pvt->outgoing && !pvt->owner)
				{
					pvt->group_last_used = 1;
					break;
				}
				ast_mutex_unlock (&pvt->lock);
			}

			ast_mutex_unlock (&round_robin_mtx);
		}
	}
	else if (((dest_dev[0] == 'p') || (dest_dev[0] == 'P')) && dest_dev[1] == ':')
	{
		ast_mutex_lock (&round_robin_mtx);

		/* Generate a list of all availible devices */
		j = sizeof (round_robin) / sizeof (round_robin[0]);
		c = 0; last_used = 0;
		AST_RWLIST_TRAVERSE (&devices, pvt, entry)
		{
			ast_mutex_lock (&pvt->lock);
			if (!strcmp (pvt->provider_name, &dest_dev[2]))
			{
				round_robin[c] = pvt;
				if (pvt->prov_last_used == 1)
				{
					pvt->prov_last_used = 0;
					last_used = c;
				}

				c++;

				if (c == j)
				{
					ast_mutex_unlock (&pvt->lock);
					break;
				}
			}
			ast_mutex_unlock (&pvt->lock);
		}

		/* Search for a availible device starting at the last used device */
		for (i = 0, j = last_used + 1; i < c; i++, j++)
		{
			if (j == c)
			{
				j = 0;
			}

			pvt = round_robin[j];

			ast_mutex_lock (&pvt->lock);
			if (pvt->connected && pvt->initialized && pvt->has_voice && pvt->gsm_registered && !pvt->incoming && !pvt->outgoing && !pvt->owner)
			{
				pvt->prov_last_used = 1;
				break;
			}
			ast_mutex_unlock (&pvt->lock);
		}

		ast_mutex_unlock (&round_robin_mtx);
	}
	else if (((dest_dev[0] == 's') || (dest_dev[0] == 'S')) && dest_dev[1] == ':')
	{
		ast_mutex_lock (&round_robin_mtx);

		/* Generate a list of all availible devices */
		j = sizeof (round_robin) / sizeof (round_robin[0]);
		c = 0; last_used = 0;
		i = strlen (&dest_dev[2]);
		AST_RWLIST_TRAVERSE (&devices, pvt, entry)
		{
			ast_mutex_lock (&pvt->lock);
			if (!strncmp (pvt->imsi, &dest_dev[2], i))
			{
				round_robin[c] = pvt;
				if (pvt->sim_last_used == 1)
				{
					pvt->sim_last_used = 0;
					last_used = c;
				}

				c++;

				if (c == j)
				{
					ast_mutex_unlock (&pvt->lock);
					break;
				}
			}
			ast_mutex_unlock (&pvt->lock);
		}

		/* Search for a availible device starting at the last used device */
		for (i = 0, j = last_used + 1; i < c; i++, j++)
		{
			if (j == c)
			{
				j = 0;
			}

			pvt = round_robin[j];

			ast_mutex_lock (&pvt->lock);
			if (pvt->connected && pvt->initialized && pvt->has_voice && pvt->gsm_registered && !pvt->incoming && !pvt->outgoing && !pvt->owner)
			{
				pvt->sim_last_used = 1;
				break;
			}
			ast_mutex_unlock (&pvt->lock);
		}

		ast_mutex_unlock (&round_robin_mtx);
	}
	else if (((dest_dev[0] == 'i') || (dest_dev[0] == 'I')) && dest_dev[1] == ':')
	{
		AST_RWLIST_TRAVERSE (&devices, pvt, entry)
		{
			ast_mutex_lock (&pvt->lock);
			if (!strcmp(pvt->imei, &dest_dev[2]))
			{
				break;
			}
			ast_mutex_unlock (&pvt->lock);
		}
	}
	else
	{
		AST_RWLIST_TRAVERSE (&devices, pvt, entry)
		{
			ast_mutex_lock (&pvt->lock);
			if (!strcmp (pvt->id, dest_dev))
			{
				break;
			}
			ast_mutex_unlock (&pvt->lock);
		}
	}

	AST_RWLIST_UNLOCK (&devices);

	if (!pvt || !pvt->connected || !pvt->initialized || !pvt->has_voice || !pvt->gsm_registered || pvt->incoming || pvt->outgoing || pvt->owner)
	{
		if (pvt)
		{
			ast_mutex_unlock (&pvt->lock);
		}
	
		ast_log (LOG_WARNING, "Request to call on device '%s' which can not make call at this moment\n", dest_dev);
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;

		return NULL;
	}

	channel = channel_new (pvt, AST_STATE_DOWN, NULL, NULL, requestor);

	ast_mutex_unlock (&pvt->lock);

	if (!channel)
	{
		ast_log (LOG_WARNING, "Unable to allocate channel structure\n");
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;

		return NULL;
	}

	return channel;
}

static int channel_call (struct ast_channel* chan, char* dest, attribute_unused int timeout)
{
	pvt_t*	pvt = ast_channel_tech_pvt (chan);
	char*	dest_dev = NULL;
	char*	dest_num = NULL;
	int	clir = 0;

	dest_dev = ast_strdupa (dest);

	if (!(dest_num = strchr (dest_dev, '/')))
	{
		ast_log (LOG_WARNING, "Can't determine destination\n");
		return -1;
	}

	*dest_num = '\0'; dest_num++;

	if (*dest_num == '\0')
	{
		ast_log (LOG_WARNING, "Empty destination\n");
		return -1;
	}

	if ((ast_channel_state (chan) != AST_STATE_DOWN) && (ast_channel_state (chan) != AST_STATE_RESERVED))
	{
		ast_log (LOG_WARNING, "channel_call called on %s, neither down nor reserved\n", ast_channel_name (chan));
		return -1;
	}

	ast_mutex_lock (&pvt->lock);

	if (!pvt->initialized || pvt->incoming || pvt->outgoing)
	{
		ast_mutex_unlock (&pvt->lock);
		ast_log (LOG_ERROR, "[%s] Error device already in use\n", pvt->id);
		return -1;
	}

	ast_debug (1, "[%s] Calling %s on %s\n", pvt->id, dest, ast_channel_name (chan));

	if (pvt->usecallingpres)
	{
		if (pvt->callingpres < 0)
		{
			clir = ast_channel_connected (chan)->id.number.presentation;
		}
		else
		{
			clir = pvt->callingpres;
		}

		clir = get_at_clir_value (pvt, clir);
		dest_num = ast_strdup (dest_num);
		if (at_send_clir (pvt, clir) || at_fifo_queue_add_ptr (pvt, CMD_AT_CLIR, RES_OK, dest_num))
		{
			ast_mutex_unlock (&pvt->lock);
			ast_log (LOG_ERROR, "[%s] Error sending AT+CLIR command\n", pvt->id);
			return -1;
		}
	}
	else
	{
		if (at_send_atd (pvt, dest_num) || at_fifo_queue_add (pvt, CMD_AT_D, RES_OK))
		{
			ast_mutex_unlock (&pvt->lock);
			ast_log (LOG_ERROR, "[%s] Error sending ATD command\n", pvt->id);
			return -1;
		}
	}

	pvt->outgoing = 1;
	pvt->needchup = 1;

	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_hangup (struct ast_channel* chan)
{
	pvt_t* pvt = ast_channel_tech_pvt (chan);

	if (!pvt)
	{
		ast_log (LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}

	ast_debug (1, "[%s] Hanging up device\n", pvt->id);

	ast_mutex_lock (&pvt->lock);

	if (pvt->a_timer)
	{
		ast_timer_close (pvt->a_timer);
		pvt->a_timer = NULL;
	}

	if (pvt->needchup)
	{
		if (at_send_chup (pvt) || at_fifo_queue_add (pvt, CMD_AT_CHUP, RES_OK))
		{
			ast_log (LOG_ERROR, "[%s] Error sending AT+CHUP command\n", pvt->id);
		}

		pvt->needchup = 0;
	}

	pvt->owner = NULL;
	pvt->needring = 0;

	ast_channel_tech_pvt_set (chan, NULL);

	ast_module_unref (ast_module_info->self);

	ast_mutex_unlock (&pvt->lock);

	ast_setstate (chan, AST_STATE_DOWN);

	return 0;
}

static int channel_answer (struct ast_channel* chan)
{
	pvt_t* pvt = ast_channel_tech_pvt (chan);

	ast_mutex_lock (&pvt->lock);

	if (pvt->incoming)
	{
		if (at_send_ata (pvt) || at_fifo_queue_add (pvt, CMD_AT_A, RES_OK))
		{
			ast_log (LOG_ERROR, "[%s] Error sending ATA command\n", pvt->id);
		}

		pvt->answered = 1;
	}

	ast_mutex_unlock (&pvt->lock);

	return 0;

}

static int channel_digit_begin (struct ast_channel* chan, char digit)
{
	pvt_t* pvt = ast_channel_tech_pvt (chan);

	ast_mutex_lock (&pvt->lock);

	if (at_send_dtmf (pvt, digit) || at_fifo_queue_add (pvt, CMD_AT_DTMF, RES_OK))
	{
		ast_mutex_unlock (&pvt->lock);
		ast_log (LOG_ERROR, "[%s] Error sending DTMF %c\n", pvt->id, digit);

		return -1;
	}

	ast_mutex_unlock (&pvt->lock);

	ast_debug (1, "[%s] Send DTMF %c\n", pvt->id, digit);

	return 0;
}

static int channel_digit_end (attribute_unused struct ast_channel* channel, attribute_unused char digit, attribute_unused unsigned int duration)
{
	return 0;
}

static struct ast_frame* channel_read (struct ast_channel* chan)
{
	pvt_t*			pvt = ast_channel_tech_pvt (chan);
	struct ast_frame*	f = &ast_null_frame;
	ssize_t			res;

	while (ast_mutex_trylock (&pvt->lock))
	{
		CHANNEL_DEADLOCK_AVOIDANCE (chan);
	}

	if (!pvt->owner || pvt->audio_fd == -1)
	{
		goto e_return;
	}

	if (pvt->a_timer && ast_channel_fdno (chan) == 1)
	{
		ast_timer_ack (pvt->a_timer, 1);
		channel_timing_write (pvt);
	}
	else
	{
		memset (&pvt->a_read_frame, 0, sizeof (struct ast_frame));

		pvt->a_read_frame.frametype	= AST_FRAME_VOICE;
		ast_format_copy (&pvt->a_read_frame.subclass.format, &chan_datacard_format);
		pvt->a_read_frame.data.ptr	= pvt->a_read_buf + AST_FRIENDLY_OFFSET;
		pvt->a_read_frame.offset	= AST_FRIENDLY_OFFSET;
//		pvt->a_read_frame.src		= AST_MODULE;

		res = read (pvt->audio_fd, pvt->a_read_frame.data.ptr, FRAME_SIZE);
		if (res <= 0)
		{
			if (errno != EAGAIN && errno != EINTR)
			{
				ast_debug (1, "[%s] Read error %d, going to wait for new connection\n", pvt->id, errno);
			}

			goto e_return;
		}

		pvt->a_read_frame.samples	= res / 2;
		pvt->a_read_frame.datalen	= res;

		f = &pvt->a_read_frame;

#if __BYTE_ORDER == __BIG_ENDIAN
		ast_frame_byteswap_le (&f);
#endif

		if (pvt->dsp)
		{
			f = ast_dsp_process (chan, pvt->dsp, f);

			if (f->frametype == AST_FRAME_DTMF_END)
			{
				ast_debug (1, "[%s] Got DTMF char %c\n", pvt->id, f->subclass.integer);
			}
		}

		if (pvt->rxgain && f->frametype == AST_FRAME_VOICE)
		{
			if (ast_frame_adjust_volume (f, pvt->rxgain) == -1)
			{
				ast_debug (1, "[%s] Volume could not be adjusted!\n", pvt->id);
			}
		}
	}

e_return:
	ast_mutex_unlock (&pvt->lock);

	return f;
}

static inline void channel_timing_write (pvt_t* pvt)
{
	size_t		used;
	int		iovcnt;
	struct iovec	iov[3];
	ssize_t		res;
	size_t		count;

	used = rb_used (&pvt->a_write_rb);

	if (used >= FRAME_SIZE)
	{
		iovcnt = rb_read_n_iov (&pvt->a_write_rb, iov, FRAME_SIZE);
		rb_read_upd (&pvt->a_write_rb, FRAME_SIZE);
	}
	else if (used > 0)
	{
		iovcnt = rb_read_all_iov (&pvt->a_write_rb, iov);
		rb_read_upd (&pvt->a_write_rb, used);

		iov[iovcnt].iov_base	= silence_frame;
		iov[iovcnt].iov_len	= FRAME_SIZE - used;
		iovcnt++;
	}
	else
	{
		iov[0].iov_base		= silence_frame;
		iov[0].iov_len		= FRAME_SIZE;
		iovcnt			= 1;
	}

	count = 0;

	while ((res = writev (pvt->audio_fd, iov, iovcnt)) < 0 && (errno == EINTR || errno == EAGAIN))
	{
		if (count++ > 10)
		{
			ast_debug (1, "Deadlock avoided for write!\n");
			return;
		}
	}

	if (res < 0 || res != FRAME_SIZE)
	{
		ast_debug (1, "[%s] Write error!\n", pvt->id);
	}
}

static int channel_write (struct ast_channel* chan, struct ast_frame* f)
{
	pvt_t*	pvt = ast_channel_tech_pvt (chan);
	ssize_t	res;
	size_t	count;

	if (f->frametype != AST_FRAME_VOICE || f->subclass.format.id != AST_FORMAT_SLINEAR)
	{
		ast_debug (5, "[%s] wrong codec on %s\n", pvt->id, ast_channel_name (chan));
		return 0;
	}

	while (ast_mutex_trylock (&pvt->lock))
	{
		CHANNEL_DEADLOCK_AVOIDANCE (chan);
	}

	if (pvt->audio_fd == -1)
	{
		ast_debug (1, "[%s] audio_fd not ready\n", pvt->id);
	}
	else
	{
		if (pvt->txgain && f->datalen > 0)
		{
			if (ast_frame_adjust_volume (f, pvt->txgain) == -1)
			{
				ast_debug (1, "[%s] Volume could not be adjusted!\n", pvt->id);
			}
		}

#if __BYTE_ORDER == __BIG_ENDIAN
		ast_frame_byteswap_le (&f);
#endif

		if (pvt->a_timer)
		{
			count = rb_free (&pvt->a_write_rb);

			if (count < (size_t) f->datalen)
			{
				rb_read_upd (&pvt->a_write_rb, f->datalen - count);
			}

			rb_write (&pvt->a_write_rb, f->data.ptr, f->datalen);
		}
		else
		{
			int		iovcnt;
			struct iovec	iov[2];

			iov[0].iov_base		= f->data.ptr;
			iov[0].iov_len		= FRAME_SIZE;
			iovcnt			= 1;

			if (f->datalen < FRAME_SIZE)
			{
				iov[0].iov_len	= f->datalen;
				iov[1].iov_base	= silence_frame;
				iov[1].iov_len	= FRAME_SIZE - f->datalen;
				iovcnt		= 2;
			}

			count = 0;

			while ((res = writev (pvt->audio_fd, iov, iovcnt)) < 0 && (errno == EINTR || errno == EAGAIN))
			{
				if (count++ > 10)
				{
					ast_debug (1, "Deadlock avoided for write!\n");
					goto e_return;
				}
			}

			if (res < 0 || res != FRAME_SIZE)
			{
				ast_debug (1, "[%s] Write error!\n", pvt->id);
			}
		}
	}

e_return:
	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_fixup (struct ast_channel* old_chan, struct ast_channel* new_chan)
{
	pvt_t* pvt = ast_channel_tech_pvt (new_chan);

	if (!pvt)
	{
		ast_debug (1, "fixup failed, no pvt on newchan\n");
		return -1;
	}

	ast_mutex_lock (&pvt->lock);
	if (pvt->owner == old_chan)
	{
		pvt->owner = new_chan;
	}
	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_devicestate (void* data)
{
	char*	device;
	pvt_t*	pvt;
	int	res = AST_DEVICE_INVALID;

	device = ast_strdupa (data ? data : "");

	ast_debug (1, "Checking device state for device %s\n", device);

	pvt = find_device (device);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected)
		{
			if (pvt->incoming || pvt->outgoing || pvt->owner)
			{
				res = AST_DEVICE_INUSE;
			}
			else
			{
				res = AST_DEVICE_NOT_INUSE;
			}
		}
		ast_mutex_unlock (&pvt->lock);
	}

	return res;
}

static int channel_indicate (struct ast_channel* chan, int condition, const void* data, attribute_unused size_t datalen)
{
	pvt_t*	pvt = ast_channel_tech_pvt (chan);
	int	res = 0;

	ast_mutex_lock (&pvt->lock);

	ast_debug (1, "[%s] Requested indication %d\n", pvt->id, condition);

	switch (condition)
	{
		case AST_CONTROL_BUSY:
		case AST_CONTROL_CONGESTION:
			break;

		case AST_CONTROL_RINGING:
//			break;

		case -1:
			res = -1;
			break;

		case AST_CONTROL_PROGRESS:
		case AST_CONTROL_PROCEEDING:
		case AST_CONTROL_VIDUPDATE:
		case AST_CONTROL_SRCUPDATE:
		case AST_CONTROL_SRCCHANGE:
		case AST_CONTROL_PVT_CAUSE_CODE:
			break;

		case AST_CONTROL_HOLD:
			ast_moh_start (chan, data, NULL);
			break;

		case AST_CONTROL_UNHOLD:
			ast_moh_stop (chan);
			break;

		default:
			ast_log (LOG_WARNING, "[%s] Don't know how to indicate condition %d\n", pvt->id, condition);
			res = -1;
			break;
	}

	ast_mutex_unlock(&pvt->lock);

	return res;
}

static int channel_queue_control (pvt_t* pvt, enum ast_control_frame_type control)
{
	for (;;)
	{
		if (pvt->owner)
		{
			if (ast_channel_trylock (pvt->owner))
			{
				DEADLOCK_AVOIDANCE (&pvt->lock);
			}
			else
			{
				ast_queue_control (pvt->owner, control);
				ast_channel_unlock (pvt->owner);

				break;
			}
		}
		else
		{
			break;
		}
	}

	return 0;
}

static int channel_queue_hangup (pvt_t* pvt, int hangupcause)
{
	for (;;)
	{
		if (pvt->owner)
		{
			if (ast_channel_trylock (pvt->owner))
			{
				DEADLOCK_AVOIDANCE (&pvt->lock);
			}
			else
			{
				if (hangupcause != 0)
				{
					ast_channel_hangupcause_set (pvt->owner, hangupcause);
				}

				ast_queue_hangup (pvt->owner);
				ast_channel_unlock (pvt->owner);

				break;
			}
		}
		else
		{
			break;
		}
	}

	return 0;
}

static int channel_ast_hangup (pvt_t* pvt)
{
	int res = 0;

	for (;;)
	{
		if (pvt->owner)
		{
			if (ast_channel_trylock (pvt->owner))
			{
				DEADLOCK_AVOIDANCE (&pvt->lock);
			}
			else
			{
				res = ast_hangup (pvt->owner);
				/* no need to unlock, ast_hangup() frees the channel */
				break;
			}
		}
		else
		{
			break;
		}
	}

	return res;
}

#ifdef __ALLOW_LOCAL_CHANNELS__
static struct ast_channel* channel_local_request (pvt_t* pvt, void* data, const char* cid_name, const char* cid_num)
{
	struct ast_channel*	chan;
	int			cause = 0;

	if (!(chan = ast_request ("Local", AST_FORMAT_TEXT_MASK, NULL, data, &cause)))
	{
		ast_log (LOG_NOTICE, "Unable to request channel Local/%s\n", (char*) data);
		return chan;
	}

	ast_set_callerid (chan, cid_num, cid_name, cid_num);
	pbx_builtin_setvar_helper (chan, "DATACARD",	pvt->id);
	pbx_builtin_setvar_helper (chan, "PROVIDER",	pvt->provider_name);
	pbx_builtin_setvar_helper (chan, "IMEI",	pvt->imei);
	pbx_builtin_setvar_helper (chan, "IMSI",	pvt->imsi);

	if (pvt->vars)
	{
		struct ast_variable*	var = NULL;
		char			vbuf[1024];

		for (var = pvt->vars; var; var = var->next)
		{
			pbx_builtin_setvar_helper (chan, var->name, ast_get_encoded_str (var->value, varbuf, sizeof (varbuf)));
		}
	}

	if (!ast_strlen_zero (pvt->language))
	{
		ast_string_field_set (chan, language, pvt->language);
	}

	return chan;
}
#endif /* __ALLOW_LOCAL_CHANNELS__ */
