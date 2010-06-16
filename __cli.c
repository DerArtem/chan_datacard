/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

static char* cli_show_devices (struct ast_cli_entry* e, int cmd, struct ast_cli_args* a)
{
	pvt_t* pvt;

#define FORMAT1 "%-12.12s %-5.5s %-9.9s %-11.11s %-5.5s %-5.5s %-3.3s %-4.4s %-4.4s %-7.7s %-14.14s %-10.10s %-17.17s %-17.17s %-14.14s\n"
#define FORMAT2 "%-12.12s %-5d %-9.9s %-11.11s %-5.5s %-5.5s %-3.3s %-4d %-4d %-7d %-14.14s %-10.10s %-17.17s %-17.17s %-14.14s\n"

	switch (cmd)
	{
		case CLI_INIT:
			e->command =	"datacard show devices";
			e->usage   =	"Usage: datacard show devices\n"
					"       Shows the state of Datacard devices.\n";
			return NULL;

		case CLI_GENERATE:
			return NULL;
	}

	if (a->argc < 3)
	{
		return CLI_SHOWUSAGE;
	}

	ast_cli (a->fd, FORMAT1, "ID", "Group", "Connected", "Initialized", "State", "Voice", "SMS", "RSSI", "Mode", "Submode", "Provider Name", "Model", "Firmware", "IMEI", "Number");

	AST_RWLIST_RDLOCK (&devices);
	AST_RWLIST_TRAVERSE (&devices, pvt, entry)
	{
		ast_mutex_lock (&pvt->lock);
		ast_cli (a->fd, FORMAT2,
			pvt->id,
			pvt->group,
			pvt->connected ? "Yes" : "No",
			pvt->initialized ? "Yes" : "No",
			(!pvt->connected) ? "None" : (pvt->outgoing || pvt->incoming) ? "Busy" : (pvt->outgoing_sms || pvt->incoming_sms) ? "SMS" : "Free",
			(pvt->has_voice) ? "Yes" : "No",
			(pvt->has_sms) ? "Yes" : "No",
			pvt->rssi,
			pvt->linkmode,
			pvt->linksubmode,
			pvt->provider_name,
			pvt->model,
			pvt->firmware,
			pvt->imei,
			pvt->number
		);
		ast_mutex_unlock (&pvt->lock);
	}
	AST_RWLIST_UNLOCK (&devices);

#undef FORMAT1
#undef FORMAT2

	return CLI_SUCCESS;
}

static char* cli_show_device (struct ast_cli_entry* e, int cmd, struct ast_cli_args* a)
{
	pvt_t* pvt;

	switch (cmd)
	{
		case CLI_INIT:
			e->command =	"datacard show device";
			e->usage   =	"Usage: datacard show device <device>\n"
					"       Shows the state and config of Datacard device.\n";
			return NULL;

		case CLI_GENERATE:
			if (a->pos == 3)
			{
				return complete_device (a->line, a->word, a->pos, a->n, 0);
			}
			return NULL;
	}

	if (a->argc < 4)
	{
		return CLI_SHOWUSAGE;
	}

	pvt = find_device (a->argv[3]);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		ast_cli (a->fd, "Device %s:\n", a->argv[3]);
		ast_mutex_unlock (&pvt->lock);
	}
	else
	{
		ast_cli (a->fd, "Device %s not found\n", a->argv[2]);
	}

	return CLI_SUCCESS;
}

static char* cli_cmd (struct ast_cli_entry* e, int cmd, struct ast_cli_args* a)
{
	pvt_t*	pvt = NULL;
	char	buf[1024];

	switch (cmd)
	{
		case CLI_INIT:
			e->command =	"datacard cmd";
			e->usage   =	"Usage: datacard cmd <device> <command>\n"
					"       Send <command> to the rfcomm port on the device\n"
					"       with the specified <device>.\n";
			return NULL;

		case CLI_GENERATE:
			if (a->pos == 2)
			{
				return complete_device (a->line, a->word, a->pos, a->n, 0);
			}
			return NULL;
	}

	if (a->argc < 4)
	{
		return CLI_SHOWUSAGE;
	}

	pvt = find_device (a->argv[2]);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected)
		{
			snprintf (buf, sizeof (buf), "%s\r", a->argv[3]);
			if (rfcomm_write (pvt->data_socket, buf) || msg_queue_push (pvt, AT_OK, AT_UNKNOWN))
			{
				ast_log (LOG_ERROR, "[%s] Error sending command: %s\n", pvt->id, a->argv[3]);
			}
		}
		else
		{
			ast_cli (a->fd, "Device %s not connected\n", a->argv[2]);
		}
		ast_mutex_unlock (&pvt->lock);
	}
	else
	{
		ast_cli (a->fd, "Device %s not found\n\n", a->argv[2]);
	}

	return CLI_SUCCESS;
}

static char* cli_cusd (struct ast_cli_entry* e, int cmd, struct ast_cli_args* a)
{
	pvt_t* pvt = NULL;

	switch (cmd)
	{
		case CLI_INIT:
			e->command = "datacard cusd";
			e->usage =
				"Usage: datacard cusd <device> <command>\n"
				"       Send cusd <command> to the datacard\n"
				"       with the specified <device>.\n";
			return NULL;

		case CLI_GENERATE:
			if (a->pos == 2)
			{
				return complete_device (a->line, a->word, a->pos, a->n, 0);
			}
			return NULL;
	}

	if (a->argc < 4)
	{
		return CLI_SHOWUSAGE;
	}

	pvt = find_device (a->argv[2]);
	if (pvt)
	{
		ast_mutex_lock (&pvt->lock);
		if (pvt->connected && pvt->initialized)
		{
			if (dc_send_cusd (pvt, a->argv[3]) || msg_queue_push (pvt, AT_OK, AT_CUSD))
			{
				ast_log (LOG_ERROR, "[%s] Error sending CUSD command\n", pvt->id);
			}
		}
		else
		{
			ast_cli (a->fd, "Device %s not connected / initialized\n", a->argv[2]);
		}
		ast_mutex_unlock (&pvt->lock);
	}
	else
	{
		ast_cli (a->fd, "Device %s not found\n", a->argv[2]);
	}

	return CLI_SUCCESS;
}
