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
