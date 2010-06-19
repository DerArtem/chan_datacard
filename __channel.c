/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

static struct ast_channel* channel_new (pvt_t* pvt, int state, char* cid_num)
{
	struct ast_channel* channel;

	pvt->answered = 0;

	ast_smoother_reset (pvt->smoother, DEVICE_FRAME_SIZE);
	ast_dsp_digitreset (pvt->dsp);

	channel = ast_channel_alloc (1, state, cid_num, pvt->id, 0, 0, pvt->context, 0, "Datacard/%s-%04lx", pvt->id, ast_random () & 0xffff);
	if (!channel)
	{
		return NULL;
	}

	channel->tech		= &channel_tech;
	channel->nativeformats	= DEVICE_FRAME_FORMAT;
	channel->rawreadformat	= DEVICE_FRAME_FORMAT;
	channel->rawwriteformat	= DEVICE_FRAME_FORMAT;
	channel->writeformat	= DEVICE_FRAME_FORMAT;
	channel->readformat	= DEVICE_FRAME_FORMAT;
	channel->tech_pvt	= pvt;

	if (state == AST_STATE_RING)
	{
		channel->rings = 1;
	}

	ast_string_field_set (channel, language, "en");
	ast_jb_configure (channel, &jbconf);

	if (pvt->audio_socket != -1)
	{
		ast_channel_set_fd (channel, 0, pvt->audio_socket);
	}

	pvt->owner = channel;

	return channel;
}

static struct ast_channel* channel_request (const char* type, int format, void* data, int* cause)
{
	int			oldformat;
	char*			dest_dev = NULL;
	char*			dest_num = NULL;
	struct ast_channel*	channel = NULL;
	pvt_t*			pvt = NULL;
	int			group;
	int			backwards = 0;
	size_t			i;
	size_t			c;
	size_t			c2;
	size_t			last_used;

	if (!data)
	{
		ast_log (LOG_WARNING, "Channel requested with no data\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;

		return NULL;
	}

	oldformat = format;
	format &= AST_FORMAT_SLINEAR;
	if (!format)
	{
		ast_log (LOG_WARNING, "Asked to get a channel of unsupported format '%d'\n", oldformat);
		*cause = AST_CAUSE_FACILITY_NOT_IMPLEMENTED;

		return NULL;
	}

	dest_dev = ast_strdupa ((char*) data);

	dest_num = strchr (dest_dev, '/');
	if (!dest_num)
	{
		ast_log (LOG_WARNING, "Can't determine destination\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;

		return NULL;
	}
	*dest_num = '\0'; dest_num++;


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
				if (pvt->group == group && pvt->connected && pvt->initialized && !pvt->owner)
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
			c2 = sizeof (round_robin) / sizeof (round_robin[0]);
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

					if (c == c2)
					{
						ast_mutex_unlock (&pvt->lock);
						break;
					}
				}
				ast_mutex_unlock (&pvt->lock);
			}

			/* Search for a availible device starting at the last used device */
			c2 = last_used;
			for (i = 0; i < c; i++)
			{
				c2++;
				if (c2 == c)
				{
					c2 = 0;
				}

				pvt = round_robin[c2];

				ast_mutex_lock (&pvt->lock);
				if (pvt->connected && pvt->initialized && !pvt->owner)
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
		c2 = sizeof (round_robin) / sizeof (round_robin[0]);
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

				if (c == c2)
				{
					ast_mutex_unlock (&pvt->lock);
					break;
				}
			}
			ast_mutex_unlock (&pvt->lock);
		}

		/* Search for a availible device starting at the last used device */
		c2 = last_used;
		for (i = 0; i < c; i++)
		{
			c2++;
			if (c2 == c)
			{
				c2 = 0;
			}

			pvt = round_robin[c2];

			ast_mutex_lock (&pvt->lock);
			if (pvt->connected && pvt->initialized && !pvt->owner)
			{
				pvt->prov_last_used = 1;
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

	if (!pvt || !pvt->connected || !pvt->initialized || pvt->incoming || pvt->outgoing || !pvt->has_voice || pvt->owner)
	{
		if (pvt)
		{
			ast_mutex_unlock (&pvt->lock);
		}
	
		ast_log (LOG_WARNING, "Request to call on device '%s' which is not connected / not initialized / not support voice / already in use\n", dest_dev);
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;

		return NULL;
	}

	channel = channel_new (pvt, AST_STATE_DOWN, NULL);
	ast_mutex_unlock (&pvt->lock);

	if (!channel)
	{
		ast_log (LOG_WARNING, "Unable to allocate channel structure\n");
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;

		return NULL;
	}

	return channel;
}

static int channel_call (struct ast_channel* channel, char* dest, int timeout)
{
	pvt_t*	pvt = channel->tech_pvt;
	char*	dest_dev = NULL;
	char*	dest_num = NULL;

	dest_dev = ast_strdupa ((char*) dest);

	dest_num = strchr (dest_dev, '/');
	if (!dest_num)
	{
		ast_log (LOG_WARNING, "Cant determine destination\n");
		return -1;
	}
	*dest_num = '\0'; dest_num++;

	if ((channel->_state != AST_STATE_DOWN) && (channel->_state != AST_STATE_RESERVED))
	{
		ast_log (LOG_WARNING, "channel_call called on %s, neither down nor reserved\n", channel->name);
		return -1;
	}

	ast_mutex_lock (&pvt->lock);

	if (!pvt->initialized || pvt->incoming || pvt->outgoing)
	{
		ast_mutex_unlock (&pvt->lock);
		ast_log (LOG_ERROR, "[%s] Error device already in use\n", pvt->id);
		return -1;
	}

	ast_debug (1, "[%s] Calling %s on %s\n", pvt->id, dest, channel->name);

	if (at_send_atd (pvt, dest_num) || at_fifo_queue_add (pvt, CMD_AT_D, RES_OK))
	{
		ast_mutex_unlock (&pvt->lock);
		ast_log (LOG_ERROR, "[%s] Error sending ATD command\n", pvt->id);
		return -1;
	}

	pvt->outgoing = 1;
	pvt->needchup = 1;

	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_hangup (struct ast_channel* channel)
{
	pvt_t* pvt;

	if (!channel->tech_pvt)
	{
		ast_log (LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}

	pvt = channel->tech_pvt;

	ast_debug (1, "[%s] Hanging up device\n", pvt->id);

	ast_mutex_lock (&pvt->lock);

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

	channel->tech_pvt = NULL;

	ast_mutex_unlock (&pvt->lock);

	ast_setstate (channel, AST_STATE_DOWN);

	return 0;
}

static int channel_answer (struct ast_channel* channel)
{
	pvt_t* pvt = channel->tech_pvt;

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

static int channel_digit_end (struct ast_channel* channel, char digit, unsigned int duration)
{
	pvt_t* pvt = channel->tech_pvt;

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

static struct ast_frame* channel_audio_read (struct ast_channel* channel)
{
	pvt_t*			pvt = channel->tech_pvt;
	struct ast_frame*	f = &ast_null_frame;
	ssize_t			res;

	ast_debug (7, "***\n");

	while (ast_mutex_trylock (&pvt->lock))
	{
		CHANNEL_DEADLOCK_AVOIDANCE (channel);
	}

	if (!pvt->owner || pvt->audio_socket == -1)
	{
		goto e_return;
	}

	memset (&pvt->frame, 0, sizeof (struct ast_frame));

//	pvt->frame.src			= "Datacard";
	pvt->frame.frametype		= AST_FRAME_VOICE;
	pvt->frame.subclass		= DEVICE_FRAME_FORMAT;
	pvt->frame.offset		= AST_FRIENDLY_OFFSET;
	pvt->frame.mallocd		= 0;
	pvt->frame.delivery.tv_sec	= 0;
	pvt->frame.delivery.tv_usec	= 0;
	pvt->frame.data.ptr		= pvt->io_buf + AST_FRIENDLY_OFFSET;

	if ((res = read (pvt->audio_socket, pvt->frame.data.ptr, DEVICE_FRAME_SIZE)) == -1)
	{
		if (errno != EAGAIN && errno != EINTR)
		{
			ast_debug (1, "[%s] Read error %d, going to wait for new connection\n", pvt->id, errno);
		}

		goto e_return;
	}

	pvt->frame.datalen = res;
	pvt->frame.samples = res / 2;

	f = ast_dsp_process (channel, pvt->dsp, &pvt->frame);

	if (pvt->rxgain != 0)
	{
		if (ast_frame_adjust_volume (f, pvt->rxgain) != 0)
		{
			ast_debug (1, "[%s] Volume could not be adjusted!\n", pvt->id);
		}
	}

e_return:
	ast_mutex_unlock (&pvt->lock);

	return f;
}

static int channel_audio_write (struct ast_channel* channel, struct ast_frame* frame)
{
	pvt_t*			pvt = channel->tech_pvt;
	struct ast_frame*	f;
	ssize_t			res;

	ast_debug (7, "***\n");

	if (frame->frametype != AST_FRAME_VOICE)
	{
		return 0;
	}

	while (ast_mutex_trylock (&pvt->lock))
	{
		CHANNEL_DEADLOCK_AVOIDANCE (channel);
	}

	ast_smoother_feed (pvt->smoother, frame);

	while ((f = ast_smoother_read (pvt->smoother)))
	{
		if (pvt->txgain != 0)
		{
			if (ast_frame_adjust_volume (f, pvt->txgain) != 0)
			{
				ast_debug (1, "[%s] Volume could not be adjusted!\n", pvt->id);
			}
		}

		if (pvt->audio_socket == -1)
		{
			ast_debug (1, "[%s] audio_socket not ready\n", pvt->id);
		}
		else
		{
			if ((res = write (pvt->audio_socket, f->data.ptr, (size_t) f->datalen)) == -1)
			{
				ast_debug (1, "[%s] Write error (%d)\n", pvt->id, errno);
			}
		}

		if (f != frame)
		{
			ast_frfree (f);
		}
	}

	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_fixup (struct ast_channel* oldchannel, struct ast_channel* newchannel)
{
	pvt_t* pvt = newchannel->tech_pvt;

	if (!pvt)
	{
		ast_debug (1, "fixup failed, no pvt on newchan\n");
		return -1;
	}

	ast_mutex_lock (&pvt->lock);
	if (pvt->owner == oldchannel)
	{
		pvt->owner = newchannel;
	}
	ast_mutex_unlock (&pvt->lock);

	return 0;
}

static int channel_devicestate (void* data)
{
	char*	device;
	pvt_t*	pvt;
	int	res = AST_DEVICE_INVALID;

	device = ast_strdupa (S_OR (data, ""));

	ast_debug (1, "Checking device state for device %s\n", device);

	pvt = find_device (device);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected)
		{
			if (pvt->owner)
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

static int channel_indicate (struct ast_channel* channel, int condition, const void* data, size_t datalen)
{
	pvt_t*	pvt = channel->tech_pvt;
	int	res = 0;

	ast_mutex_lock (&pvt->lock);

	ast_debug (1, "[%s] Requested indication %d\n", pvt->id, condition);

	switch (condition)
	{
		case AST_CONTROL_BUSY:
			break;

		case AST_CONTROL_CONGESTION:
			break;

		case AST_CONTROL_RINGING:
			break;

		case -1:
			res = -1;  /* Ask for inband indications */
			break;

		case AST_CONTROL_PROGRESS:
			break;

		case AST_CONTROL_PROCEEDING:
			break;

		case AST_CONTROL_VIDUPDATE:
			break;

		case AST_CONTROL_SRCUPDATE:
			break;

		case AST_CONTROL_HOLD:
			ast_moh_start (channel, data, NULL);
			break;

		case AST_CONTROL_UNHOLD:
			ast_moh_stop (channel);
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
					pvt->owner->hangupcause = hangupcause;
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
