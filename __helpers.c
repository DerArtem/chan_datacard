static pvt_t* find_device (const char* name)
{
	pvt_t*	pvt = NULL;

	AST_RWLIST_RDLOCK (&devices);
	AST_RWLIST_TRAVERSE (&devices, pvt, entry)
	{
		if (!strcmp (pvt->id, name))
		{
			break;
		}
	}
	AST_RWLIST_UNLOCK (&devices);

	return pvt;
}

static char* complete_device (const char* line, const char* word, int pos, int state, int flags)
{
	pvt_t*	pvt;
	char*	res = NULL;
	int	which = 0;
	int	wordlen = strlen (word);

	AST_RWLIST_RDLOCK (&devices);
	AST_RWLIST_TRAVERSE (&devices, pvt, entry)
	{
		if (!strncasecmp (pvt->id, word, wordlen) && ++which > state)
		{
			res = ast_strdup (pvt->id);
			break;
		}
	}
	AST_RWLIST_UNLOCK (&devices);

	return res;
}

static inline int get_clir_value (pvt_t* pvt, struct ast_channel* channel)
{
	int res = 0;

	switch (channel->cid.cid_pres)
	{
		case AST_PRES_ALLOWED_NETWORK_NUMBER:
		case AST_PRES_ALLOWED_USER_NUMBER_FAILED_SCREEN:
		case AST_PRES_ALLOWED_USER_NUMBER_NOT_SCREENED:
		case AST_PRES_ALLOWED_USER_NUMBER_PASSED_SCREEN:
		case AST_PRES_NUMBER_NOT_AVAILABLE:

			ast_debug (2, "[%s] callingpres: %s\n", pvt->id, ast_describe_caller_presentation (channel->cid.cid_pres));
			res = 2;
			break;

		case AST_PRES_PROHIB_NETWORK_NUMBER:
		case AST_PRES_PROHIB_USER_NUMBER_FAILED_SCREEN:
		case AST_PRES_PROHIB_USER_NUMBER_NOT_SCREENED:
		case AST_PRES_PROHIB_USER_NUMBER_PASSED_SCREEN:

			ast_debug (2, "[%s] callingpres: %s\n", pvt->id, ast_describe_caller_presentation (channel->cid.cid_pres));
			res = 1;
			break;

		default:
			ast_log (LOG_WARNING, "[%s] Unsupported callingpres: %d\n", pvt->id, channel->cid.cid_pres);
			if ((channel->cid.cid_pres & AST_PRES_RESTRICTION) != AST_PRES_ALLOWED)
			{
				res = 0;
			}
			else
			{
				res = 2;
			}
			break;
	}

	return res;
}
