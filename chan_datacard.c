/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2006, Digium, Inc.
 * Copyright (C) 2009 Artem Makhutov
 *
 * Artem Makhutov <artem@makhutov.org>
 *
 * chan_datacard is based on chan_mobile by Digium
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief UMTS Voice Datacard channel driver
 *
 * \author Artem Makhutov <artem@makhutov.org>
 * \author Dave Bowerman <david.bowerman@gmail.com>
 *
 * \ingroup channel_drivers
 */

#include <asterisk.h>

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 947 $")

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <signal.h>

#include <asterisk/lock.h>
#include <asterisk/channel.h>
#include <asterisk/config.h>
#include <asterisk/logger.h>
#include <asterisk/module.h>
#include <asterisk/pbx.h>
#include <asterisk/options.h>
#include <asterisk/utils.h>
#include <asterisk/linkedlists.h>
#include <asterisk/cli.h>
#include <asterisk/devicestate.h>
#include <asterisk/causes.h>
#include <asterisk/dsp.h>
#include <asterisk/app.h>
#include <asterisk/manager.h>
#include <asterisk/io.h>

#define DC_CONFIG "datacard.conf"

#define DEVICE_FRAME_SIZE 320
#define DEVICE_FRAME_FORMAT AST_FORMAT_SLINEAR
#define CHANNEL_FRAME_SIZE 320

static int prefformat = DEVICE_FRAME_FORMAT;

static int discovery_interval = 60;			/* The device discovery interval, default 60 seconds. */
static pthread_t discovery_thread = AST_PTHREADT_NULL;	/* The discovery thread */

AST_MUTEX_DEFINE_STATIC(unload_mutex);
static int unloading_flag = 0;
static inline int check_unloading();
static inline void set_unloading();

struct msg_queue_entry;
struct dc_pvt {
	struct ast_channel *owner;			/* Channel we belong to, possibly NULL */
	struct ast_frame fr;				/* "null" frame */
	ast_mutex_t lock;				/*!< pvt lock */
	/*! queue for messages we are expecting */
	AST_LIST_HEAD_NOLOCK(msg_queue, msg_queue_entry) msg_queue;
	char id[31];					/* The id from datacard.conf */
	int group;					/* group number for group dialling */
	char context[AST_MAX_CONTEXT];			/* the context for incoming calls */
	struct dc_pvt *pvt;				/*!< pvt pvt */
	char rfcomm_buf[256];
	char io_buf[CHANNEL_FRAME_SIZE + AST_FRIENDLY_OFFSET];
	struct ast_smoother *smoother;			/* our smoother, for making 48 byte frames */
	char audio_tty_str[256];
	char data_tty_str[256];
	int audio_socket;				/* sco socket descriptor */
	int data_socket;				/* rfcomm socket descriptor */
	pthread_t monitor_thread;			/* monitor thread handle */
	int timeout;					/*!< used to set the timeout for rfcomm data (may be used in the future) */
	unsigned int has_sms:1;
	unsigned int has_voice:1;
	unsigned int do_alignment_detection:1;
	unsigned int alignment_detection_triggered:1;
	short alignment_samples[4];
	int alignment_count;
	struct ast_dsp *dsp;
	int hangupcause;
	int initialized:1;		/*!< whether a service level connection exists or not */
	int rssi;
	int linkmode;
	int linksubmode;
	int volume_adjustment;

	/* flags */
	unsigned int outgoing:1;	/*!< outgoing call */
	unsigned int incoming:1;	/*!< incoming call */
	unsigned int outgoing_sms:1;	/*!< outgoing sms */
	unsigned int incoming_sms:1;	/*!< outgoing sms */
	unsigned int needchup:1;	/*!< we need to send a chup */
	unsigned int needring:1;	/*!< we need to send a RING */
	unsigned int answered:1;	/*!< we sent/recieved an answer */
	unsigned int connected:1;	/*!< do we have an rfcomm connection to a device */
	unsigned int volume_synchronized:1;	/*!< we have synchronized the volume */
	unsigned int group_last_used:1; /*!< mark the last used device */

	AST_LIST_ENTRY(dc_pvt) entry;
};

static AST_RWLIST_HEAD_STATIC(devices, dc_pvt);

static void inline rfcomm_append_buf(char **buf, size_t count, size_t *in_count, char c);
static int rfcomm_read_and_expect_char(int data_socket, char *result, char expected);
static int rfcomm_read_and_append_char(int data_socket, char **buf, size_t count, size_t *in_count, char *result, char expected);
static int rfcomm_read_until_crlf(int data_socket, char **buf, size_t count, size_t *in_count);
static int rfcomm_read_sms_prompt(int data_socket, char **buf, size_t count, size_t *in_count);
static int rfcomm_read_result(int data_socket, char **buf, size_t count, size_t *in_count);
static int rfcomm_read_command(int data_socket, char **buf, size_t count, size_t *in_count);

static int handle_response_ok(struct dc_pvt *pvt, char *buf);
static int handle_response_error(struct dc_pvt *pvt, char *buf);
static int handle_response_clip(struct dc_pvt *pvt, char *buf);
static int handle_response_ring(struct dc_pvt *pvt, char *buf);
static int handle_response_cmti(struct dc_pvt *pvt, char *buf);
static int handle_response_cmgr(struct dc_pvt *pvt, char *buf);
static int handle_response_cusd(struct dc_pvt *pvt, char *buf);
static int handle_response_busy(struct dc_pvt *pvt);
static int handle_response_no_dialtone(struct dc_pvt *pvt, char *buf);
static int handle_response_no_carrier(struct dc_pvt *pvt, char *buf);
static int handle_response_conn(struct dc_pvt *pvt, char *buf);
static int handle_response_orig(struct dc_pvt *pvt, char *buf);
static int handle_response_cssi(struct dc_pvt *pvt, char *buf);
static int handle_response_cssu(struct dc_pvt *pvt, char *buf);
static int handle_response_cpin(struct dc_pvt *pvt, char *buf);
static int handle_response_rssi(struct dc_pvt *pvt, char *buf);
static int handle_response_mode(struct dc_pvt *pvt, char *buf);
static int handle_sms_prompt(struct dc_pvt *pvt, char *buf);

/* CLI stuff */
static char *handle_cli_dc_show_devices(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_dc_rfcomm(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);
static char *handle_cli_dc_cusd(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a);

static struct ast_cli_entry dc_cli[] = {
	AST_CLI_DEFINE(handle_cli_dc_show_devices, "Show Datacard devices"),
	AST_CLI_DEFINE(handle_cli_dc_rfcomm,       "Send commands to the rfcomm port for debugging"),
	AST_CLI_DEFINE(handle_cli_dc_cusd,         "Send CUSD commands to the datacard"),
};

/* App stuff */
static char *app_dcstatus = "DatacardStatus";
static char *dcstatus_synopsis = "DatacardStatus(Device,Variable)";
static char *dcstatus_desc =
"DatacardStatus(Device,Variable)\n"
"  Device - Id of device from datacard.conf\n"
"  Variable - Variable to store status in will be 1-3.\n"
"             In order, Disconnected, Connected & Free, Connected & Busy.\n";

static char *app_dcsendsms = "DatacardSendSMS";
static char *dcsendsms_synopsis = "DatacardSendSMS(Device,Dest,Message)";
static char *dcsendsms_desc =
"DatacardSendSms(Device,Dest,Message)\n"
"  Device - Id of device from datacard.conf\n"
"  Dest - destination\n"
"  Message - text of the message\n";

static struct ast_channel *dc_new(int state, struct dc_pvt *pvt, char *cid_num);
static struct ast_channel *dc_request(const char *type, int format, void *data, int *cause);
static int dc_call(struct ast_channel *ast, char *dest, int timeout);
static int dc_hangup(struct ast_channel *ast);
static int dc_answer(struct ast_channel *ast);
static int dc_digit_end(struct ast_channel *ast, char digit, unsigned int duration);
static struct ast_frame *dc_audio_read(struct ast_channel *ast);
static int dc_audio_write(struct ast_channel *ast, struct ast_frame *frame);
static int dc_fixup(struct ast_channel *oldchan, struct ast_channel *newchan);
static int dc_devicestate(void *data);

static void do_alignment_detection(struct dc_pvt *pvt, char *buf, int buflen);

static int dc_queue_control(struct dc_pvt *pvt, enum ast_control_frame_type control);
static int dc_queue_hangup(struct dc_pvt *pvt);
static int dc_ast_hangup(struct dc_pvt *pvt);

static int dc_data_connect(char *data_tty_str);
static int dc_audio_connect(char *audio_tty_str);
static int disconnect_datacard(struct dc_pvt *pvt);
static int opentty(char *iface);
static int rfcomm_write(int data_socket, char *buf);
static int rfcomm_write_full(int data_socket, char *buf, size_t count);
static int rfcomm_wait(int data_socket, int *ms);
static ssize_t rfcomm_read(int data_socket, char *buf, size_t count);

static int audio_write(int s, char *buf, int len);

static char *dc_parse_clip(struct dc_pvt *pvt, char *buf);
static int dc_parse_cmti(struct dc_pvt *pvt, char *buf);
static int dc_parse_cmgr(struct dc_pvt *pvt, char *buf, char **from_number, char **text);
static char *dc_parse_cusd(struct dc_pvt *pvt, char *buf);
static int dc_parse_cpin(struct dc_pvt *pvt, char *buf);
static int dc_parse_rssi(struct dc_pvt *pvt, char *buf);
static int dc_parse_linkmode(struct dc_pvt *pvt, char *buf);
static int dc_parse_linksubmode(struct dc_pvt *pvt, char *buf);


static int dc_send_cpin_test(struct dc_pvt *pvt);
static int dc_send_clip(struct dc_pvt *pvt, int status);
static int dc_send_ddsetex(struct dc_pvt *pvt);
static int dc_send_cvoice_test(struct dc_pvt *pvt);
static int dc_send_cssn(struct dc_pvt *pvt, int cssi, int cssu);

#if 0
static int dc_send_vgm(struct dc_pvt *pvt, int value);
#endif
static int dc_send_dtmf(struct dc_pvt *pvt, char digit);
static int dc_send_cmgf(struct dc_pvt *pvt, int mode);
static int dc_send_cnmi(struct dc_pvt *pvt);
static int dc_send_cmgr(struct dc_pvt *pvt, int index);
static int dc_send_cmgs(struct dc_pvt *pvt, const char *number);
static int dc_send_sms_text(struct dc_pvt *pvt, const char *message);
static int dc_send_chup(struct dc_pvt *pvt);
static int dc_send_atd(struct dc_pvt *pvt, const char *number);
static int dc_send_ata(struct dc_pvt *pvt);
static int dc_send_cusd(struct dc_pvt *pvt, const char *code);
static int dc_send_clvl(struct dc_pvt *pvt, int level);

/*
 * Hayes AT command helpers
 */
typedef enum {
	/* errors */
	AT_PARSE_ERROR = -2,
	AT_READ_ERROR = -1,
	AT_UNKNOWN = 0,
	/* at responses */
	AT_OK,
	AT_ERROR,
	AT_RING,
	AT_CLIP,
	AT_CMTI,
	AT_CMGR,
	AT_SMS_PROMPT,
	AT_CMS_ERROR,
	/* at commands */
	AT_A,
	AT_D,
	AT_E0,
	AT_DDSETEX,
	AT_CVOICE,
	AT_CONN,
	AT_CEND,
	AT_CONF,
	AT_ORIG,
	AT_RSSI,
	AT_BOOT,
	AT_CSSN,
	AT_CSSI,
	AT_CSSU,
	AT_CHUP,
	AT_CKPD,
	AT_CMGS,
	AT_VGM,
	AT_VGS,
	AT_VTS,
	AT_CMGF,
	AT_CNMI,
	AT_CUSD,
	AT_BUSY,
	AT_NO_DIALTONE,
	AT_NO_CARRIER,
	AT_CPIN,
	AT_MODE,
	AT_CLVL,
	AT_CPMS,
	AT_SIMST,
	AT_SRVST,
} at_message_t;

static int at_match_prefix(char *buf, char *prefix);
static at_message_t at_read_full(int data_socket, char *buf, size_t count);
static inline const char *at_msg2str(at_message_t msg);

struct msg_queue_entry {
	at_message_t expected;
	at_message_t response_to;
	void *data;

	AST_LIST_ENTRY(msg_queue_entry) entry;
};

static int msg_queue_push(struct dc_pvt *pvt, at_message_t expect, at_message_t response_to);
static int msg_queue_push_data(struct dc_pvt *pvt, at_message_t expect, at_message_t response_to, void *data);
static struct msg_queue_entry *msg_queue_pop(struct dc_pvt *pvt);
static void msg_queue_free_and_pop(struct dc_pvt *pvt);
static void msg_queue_flush(struct dc_pvt *pvt);
static struct msg_queue_entry *msg_queue_head(struct dc_pvt *pvt);

/*
 * channel stuff
 */

static const struct ast_channel_tech dc_tech = {
	.type = "Datacard",
	.description = "Datacard Channel Driver",
	.capabilities = AST_FORMAT_SLINEAR,
	.requester = dc_request,
	.call = dc_call,
	.hangup = dc_hangup,
	.answer = dc_answer,
	.send_digit_end = dc_digit_end,
	.read = dc_audio_read,
	.write = dc_audio_write,
	.fixup = dc_fixup,
	.devicestate = dc_devicestate
};

/* CLI Commands implementation */

static char *handle_cli_dc_show_devices(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	struct dc_pvt *pvt;
	char group[6];
	char rssi[6];
	char linkmode[6];
	char linksubmode[6];

#define FORMAT1 "%-15.15s %-6.6s %-9.9s %-5.5s %-5.5s %-5.5s %-5.5s %-5.5s %-7.7s\n"

	switch (cmd) {
	case CLI_INIT:
		e->command = "datacard show devices";
		e->usage =
			"Usage: datacard show devices\n"
			"       Shows the state of Datacard devices.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 3)
		return CLI_SHOWUSAGE;

	ast_cli(a->fd, FORMAT1, "ID", "Group", "Connected", "State", "Voice", "SMS", "RSSI", "Mode", "Submode");
	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		ast_mutex_lock(&pvt->lock);
		snprintf(group, sizeof(group), "%d", pvt->group);
		snprintf(rssi, sizeof(rssi), "%d", pvt->rssi);
		snprintf(linkmode, sizeof(linkmode), "%d", pvt->linkmode);
		snprintf(linksubmode, sizeof(linksubmode), "%d", pvt->linksubmode);
		ast_cli(a->fd, FORMAT1,
				pvt->id,
				group,
				pvt->connected ? "Yes" : "No",
				(!pvt->connected) ? "None" : (pvt->outgoing || pvt->incoming) ? "Busy" : (pvt->outgoing_sms || pvt->incoming_sms) ? "SMS" : "Free",
				(pvt->has_voice) ? "Yes" : "No",
				(pvt->has_sms) ? "Yes" : "No",
				rssi,
				linkmode,
				linksubmode
		       );
		ast_mutex_unlock(&pvt->lock);
	}
	AST_RWLIST_UNLOCK(&devices);

#undef FORMAT1

	return CLI_SUCCESS;
}

static char *handle_cli_dc_rfcomm(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char buf[128];
	struct dc_pvt *pvt = NULL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "datacard rfcomm";
		e->usage =
			"Usage: datacard rfcomm <device ID> <command>\n"
			"       Send <command> to the rfcomm port on the device\n"
			"       with the specified <device ID>.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4)
		return CLI_SHOWUSAGE;

	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		if (!strcmp(pvt->id, a->argv[2]))
			break;
	}
	AST_RWLIST_UNLOCK(&devices);

	if (!pvt) {
		ast_cli(a->fd, "Device %s not found.\n", a->argv[2]);
		goto e_return;
	}

	ast_mutex_lock(&pvt->lock);
	if (!pvt->connected) {
		ast_cli(a->fd, "Device %s not connected.\n", a->argv[2]);
		goto e_unlock_pvt;
	}

	snprintf(buf, sizeof(buf), "%s\r", a->argv[3]);
	rfcomm_write(pvt->data_socket, buf);
	msg_queue_push(pvt, AT_OK, AT_UNKNOWN);

e_unlock_pvt:
	ast_mutex_unlock(&pvt->lock);
e_return:
	return CLI_SUCCESS;
}

static char *handle_cli_dc_cusd(struct ast_cli_entry *e, int cmd, struct ast_cli_args *a)
{
	char buf[128];
	struct dc_pvt *pvt = NULL;

	switch (cmd) {
	case CLI_INIT:
		e->command = "datacard cusd";
		e->usage =
			"Usage: datacard cusd <device ID> <command>\n"
			"       Send cusd <command> to the datacard\n"
			"       with the specified <device ID>.\n";
		return NULL;
	case CLI_GENERATE:
		return NULL;
	}

	if (a->argc != 4)
		return CLI_SHOWUSAGE;

	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		if (!strcmp(pvt->id, a->argv[2]))
			break;
	}
	AST_RWLIST_UNLOCK(&devices);

	if (!pvt) {
		ast_cli(a->fd, "Device %s not found.\n", a->argv[2]);
		goto e_return;
	}

	ast_mutex_lock(&pvt->lock);
	if (!pvt->connected) {
		ast_cli(a->fd, "Device %s not connected.\n", a->argv[2]);
		goto e_unlock_pvt;
	}

	snprintf(buf, sizeof(buf), "%s", a->argv[3]);
	dc_send_cusd(pvt, buf);
	msg_queue_push(pvt, AT_OK, AT_CUSD);

e_unlock_pvt:
	ast_mutex_unlock(&pvt->lock);
e_return:
	return CLI_SUCCESS;
}

/*

	Dialplan applications implementation

*/

static int dc_status_exec(struct ast_channel *ast, const char *data)
{

	struct dc_pvt *pvt;
	char *parse;
	int stat;
	char status[2];

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(device);
		AST_APP_ARG(variable);
	);

	if (ast_strlen_zero(data))
		return -1;

	parse = ast_strdupa(data);

	AST_STANDARD_APP_ARGS(args, parse);

	if (ast_strlen_zero(args.device) || ast_strlen_zero(args.variable))
		return -1;

	stat = 1;

	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		if (!strcmp(pvt->id, args.device))
			break;
	}
	AST_RWLIST_UNLOCK(&devices);

	if (pvt) {
		ast_mutex_lock(&pvt->lock);
		if (pvt->connected)
			stat = 2;
		if (pvt->owner)
			stat = 3;
		ast_mutex_unlock(&pvt->lock);
	}

	snprintf(status, sizeof(status), "%d", stat);
	pbx_builtin_setvar_helper(ast, args.variable, status);

	return 0;

}

static int dc_sendsms_exec(struct ast_channel *ast, const char *data)
{

	struct dc_pvt *pvt;
	char *parse, *message;

	AST_DECLARE_APP_ARGS(args,
		AST_APP_ARG(device);
		AST_APP_ARG(dest);
		AST_APP_ARG(message);
	);

	if (ast_strlen_zero(data))
		return -1;

	parse = ast_strdupa(data);

	AST_STANDARD_APP_ARGS(args, parse);

	if (ast_strlen_zero(args.device)) {
		ast_log(LOG_ERROR,"NULL device for message -- SMS will not be sent.\n");
		return -1;
	}

	if (ast_strlen_zero(args.dest)) {
		ast_log(LOG_ERROR,"NULL destination for message -- SMS will not be sent.\n");
		return -1;
	}

	if (ast_strlen_zero(args.message)) {
		ast_log(LOG_ERROR,"NULL Message to be sent -- SMS will not be sent.\n");
		return -1;
	}

	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		if (!strcmp(pvt->id, args.device))
			break;
	}
	AST_RWLIST_UNLOCK(&devices);

	if (!pvt) {
		ast_log(LOG_ERROR,"Datacard %s wasn't found in the list -- SMS will not be sent.\n", args.device);
		goto e_return;
	}

	ast_mutex_lock(&pvt->lock);
	if (!pvt->connected) {
		ast_log(LOG_ERROR,"Datacard %s wasn't connected -- SMS will not be sent.\n", args.device);
		goto e_unlock_pvt;
	}

	if (!pvt->has_sms) {
		ast_log(LOG_ERROR,"Datacard %s doesn't handle SMS -- SMS will not be sent.\n", args.device);
		goto e_unlock_pvt;
	}

	message = ast_strdup(args.message);

	if (dc_send_cmgs(pvt, args.dest)
		|| msg_queue_push_data(pvt, AT_SMS_PROMPT, AT_CMGS, message)) {

		ast_log(LOG_ERROR, "[%s] problem sending SMS message\n", pvt->id);
		goto e_free_message;
	}

	ast_mutex_unlock(&pvt->lock);

	return 0;

e_free_message:
	ast_free(message);
e_unlock_pvt:
	ast_mutex_unlock(&pvt->lock);
e_return:
	return -1;
}

/*

	Channel Driver callbacks

*/

static struct ast_channel *dc_new(int state, struct dc_pvt *pvt, char *cid_num)
{

	struct ast_channel *chn;

	pvt->answered = 0;
	pvt->alignment_count = 0;
	pvt->alignment_detection_triggered = 0;

	ast_smoother_reset(pvt->smoother, DEVICE_FRAME_SIZE);
	ast_dsp_digitreset(pvt->dsp);

	chn = ast_channel_alloc(1, state, cid_num, pvt->id, 0, 0, pvt->context, 0, "Datacard/%s-%04lx", pvt->id, ast_random() & 0xffff);
	if (!chn) {
		goto e_return;
	}

	chn->tech = &dc_tech;
	chn->nativeformats = prefformat;
	chn->rawreadformat = prefformat;
	chn->rawwriteformat = prefformat;
	chn->writeformat = prefformat;
	chn->readformat = prefformat;
	chn->tech_pvt = pvt;

	if (state == AST_STATE_RING)
		chn->rings = 1;

	ast_string_field_set(chn, language, "en");
	pvt->owner = chn;

	if (pvt->audio_socket != -1) {
		ast_channel_set_fd(chn, 0, pvt->audio_socket);
	}

	return chn;

e_return:
	return NULL;
}

static struct ast_channel *dc_request(const char *type, int format, void *data, int *cause)
{

	struct ast_channel *chn = NULL;
	struct dc_pvt *pvt;
	struct dc_pvt *device_list[256];
	char *dest_dev = NULL;
	char *dest_num = NULL;
	int oldformat, group = -1;
	int loop_count = 0;
	int loop_count2 = 0;
	int last_used_device = 0;
	int i = 0;
	for (i=0;i<256;i++) {
		device_list[i] = NULL;
	}

	if (!data) {
		ast_log(LOG_WARNING, "Channel requested with no data\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;
		return NULL;
	}

	oldformat = format;
	format &= (AST_FORMAT_SLINEAR);
	if (!format) {
		ast_log(LOG_WARNING, "Asked to get a channel of unsupported format '%d'\n", oldformat);
		*cause = AST_CAUSE_FACILITY_NOT_IMPLEMENTED;
		return NULL;
	}

	dest_dev = ast_strdupa((char *)data);

	dest_num = strchr(dest_dev, '/');
	if (dest_num)
		*dest_num++ = 0x00;

	/* Find requested device and make sure it's connected. */
	if (((dest_dev[0] == 'g') || (dest_dev[0] == 'G')) && ((dest_dev[1] >= '0') && (dest_dev[1] <= '9'))) {
		group = atoi(&dest_dev[1]);
		AST_RWLIST_RDLOCK(&devices);
		AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
			if (group > -1 && pvt->group == group && pvt->connected && !pvt->owner) {
				break;
			}
		}
		AST_RWLIST_UNLOCK(&devices);
	}
	else if (((dest_dev[0] == 'r') || (dest_dev[0] == 'R')) && ((dest_dev[1] >= '0') && (dest_dev[1] <= '9'))) {
		group = atoi(&dest_dev[1]);
		AST_RWLIST_RDLOCK(&devices);
		
		// Generate a list of all availible devices
		AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
			if (group > -1 && pvt->group == group) {
				device_list[loop_count] = pvt;
				loop_count++;
			}
		}

		// Find last used device
		for (i=0;i<loop_count;i++) {
			if (device_list[i]->group_last_used == 1) {
				last_used_device = i;
				device_list[i]->group_last_used = 0;
				break;
			}
		}

		// Search for a availible device starting at the last used device 
		loop_count2 = last_used_device;

		for (i=0;i<loop_count;i++) {
			loop_count2++;
			if (loop_count2 == loop_count) {
				loop_count2 = 0;
			}

			pvt=device_list[loop_count2];

			if (pvt->connected && !pvt->owner) {
				pvt->group_last_used = 1;
				break;
			}
		}

		AST_RWLIST_UNLOCK(&devices);
	}
	else {
		AST_RWLIST_RDLOCK(&devices);
		AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
			if (!strcmp(pvt->id, dest_dev)) {
				break;
			}
		}
		AST_RWLIST_UNLOCK(&devices);
	}

	if (!pvt || !pvt->connected || pvt->owner) {
		ast_log(LOG_WARNING, "Request to call on device %s which is not connected / already in use.\n", dest_dev);
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;
		return NULL;
	}

	if (!dest_num) {
		ast_log(LOG_WARNING, "Can't determine destination number.\n");
		*cause = AST_CAUSE_INCOMPATIBLE_DESTINATION;
		return NULL;
	}

	ast_mutex_lock(&pvt->lock);
	chn = dc_new(AST_STATE_DOWN, pvt, NULL);
	ast_mutex_unlock(&pvt->lock);
	if (!chn) {
		ast_log(LOG_WARNING, "Unable to allocate channel structure.\n");
		*cause = AST_CAUSE_REQUESTED_CHAN_UNAVAIL;
		return NULL;
	}

	return chn;

}

static int dc_call(struct ast_channel *ast, char *dest, int timeout)
{

	struct dc_pvt *pvt;
	char *dest_dev = NULL;
	char *dest_num = NULL;

	dest_dev = ast_strdupa((char *)dest);

	pvt = ast->tech_pvt;

	dest_num = strchr(dest_dev, '/');
	if (!dest_num) {
		ast_log(LOG_WARNING, "Cant determine destination number.\n");
		return -1;
	}
	*dest_num++ = 0x00;

	if ((ast->_state != AST_STATE_DOWN) && (ast->_state != AST_STATE_RESERVED)) {
		ast_log(LOG_WARNING, "dc_call called on %s, neither down nor reserved\n", ast->name);
		return -1;
	}

	ast_debug(1, "Calling %s on %s\n", dest, ast->name);

	ast_mutex_lock(&pvt->lock);

	if (dc_send_atd(pvt, dest_num)) {
		ast_mutex_unlock(&pvt->lock);
		ast_log(LOG_ERROR, "error sending ATD command on %s\n", pvt->id);
		return -1;
	}
	pvt->hangupcause = 0;
	pvt->needchup = 1;
	pvt->outgoing = 1;
	msg_queue_push(pvt, AT_OK, AT_D);
	
	ast_mutex_unlock(&pvt->lock);

	return 0;

}

static int dc_hangup(struct ast_channel *ast)
{

	struct dc_pvt *pvt;

	if (!ast->tech_pvt) {
		ast_log(LOG_WARNING, "Asked to hangup channel not connected\n");
		return 0;
	}
	pvt = ast->tech_pvt;

	ast_debug(1, "[%s] hanging up device\n", pvt->id);

	ast_mutex_lock(&pvt->lock);

	if (pvt->needchup) {
		dc_send_chup(pvt);
		msg_queue_push(pvt, AT_OK, AT_CHUP);
		pvt->needchup = 0;
	}

	pvt->outgoing = 0;
	pvt->incoming = 0;
	pvt->needring = 0;
	pvt->owner = NULL;
	ast->tech_pvt = NULL;

	ast_mutex_unlock(&pvt->lock);

	ast_setstate(ast, AST_STATE_DOWN);

	return 0;

}

static int dc_answer(struct ast_channel *ast)
{

	struct dc_pvt *pvt;

	pvt = ast->tech_pvt;

	ast_mutex_lock(&pvt->lock);
	if (pvt->incoming) {
		dc_send_ata(pvt);
		msg_queue_push(pvt, AT_OK, AT_A);
		pvt->answered = 1;
	}
	ast_mutex_unlock(&pvt->lock);

	return 0;

}

static int dc_digit_end(struct ast_channel *ast, char digit, unsigned int duration)
{
	struct dc_pvt *pvt = ast->tech_pvt;

	ast_mutex_lock(&pvt->lock);
	if (dc_send_dtmf(pvt, digit)) {
		ast_mutex_unlock(&pvt->lock);
		ast_debug(1, "[%s] error sending digit %c\n", pvt->id, digit);
		return -1;
	}
	msg_queue_push(pvt, AT_OK, AT_VTS);
	ast_mutex_unlock(&pvt->lock);

	ast_debug(1, "[%s] dialed %c\n", pvt->id, digit);

	return 0;
}

static struct ast_frame *dc_audio_read(struct ast_channel *ast)
{

	struct dc_pvt *pvt = ast->tech_pvt;
	struct ast_frame *fr = &ast_null_frame;
	int r;

	ast_debug(3, "*** dc_audio_read()\n");

	while (ast_mutex_trylock(&pvt->lock)) {
		CHANNEL_DEADLOCK_AVOIDANCE(ast);
	}

	if (!pvt->owner || pvt->audio_socket == -1) {
		goto e_return;
	}

	memset(&pvt->fr, 0x00, sizeof(struct ast_frame));
	pvt->fr.frametype = AST_FRAME_VOICE;
	pvt->fr.subclass = DEVICE_FRAME_FORMAT;
	pvt->fr.src = "Datacard";
	pvt->fr.offset = AST_FRIENDLY_OFFSET;
	pvt->fr.mallocd = 0;
	pvt->fr.delivery.tv_sec = 0;
	pvt->fr.delivery.tv_usec = 0;
	pvt->fr.data.ptr = pvt->io_buf + AST_FRIENDLY_OFFSET;

	if ((r = read(pvt->audio_socket, pvt->fr.data.ptr, DEVICE_FRAME_SIZE)) == -1) {
		if (errno != EAGAIN && errno != EINTR) {
			ast_debug(1, "[%s] read error %d, going to wait for new connection\n", pvt->id, errno);
			//close(pvt->audio_socket);
			//pvt->audio_socket = -1;
			//ast_channel_set_fd(ast, 0, -1);
		}
		goto e_return;
	}

	pvt->fr.datalen = r;
	pvt->fr.samples = r / 2;

	do_alignment_detection(pvt, pvt->fr.data.ptr, r);

	fr = ast_dsp_process(ast, pvt->dsp, &pvt->fr);

	if (pvt->volume_adjustment!=0) {
		// Lets adjust the volume of the incoming audio
		if (ast_frame_adjust_volume(fr, pvt->volume_adjustment) != 0) {
			ast_debug(1, "[%s] volume could not be adjusted!\n", pvt->id);
		}
	}

	ast_mutex_unlock(&pvt->lock);

	return fr;

e_return:
	ast_mutex_unlock(&pvt->lock);
	return fr;
}

static int dc_audio_write(struct ast_channel *ast, struct ast_frame *frame)
{

	struct dc_pvt *pvt = ast->tech_pvt;
	struct ast_frame *f;

	ast_debug(3, "*** dc_write\n");

	if (frame->frametype != AST_FRAME_VOICE) {
		return 0;
	}

	while (ast_mutex_trylock(&pvt->lock)) {
		CHANNEL_DEADLOCK_AVOIDANCE(ast);
	}

	ast_smoother_feed(pvt->smoother, frame);

	while ((f = ast_smoother_read(pvt->smoother))) {
		audio_write(pvt->audio_socket, f->data.ptr, f->datalen);
		ast_frfree(f);
	}

	ast_mutex_unlock(&pvt->lock);

	return 0;

}

static int dc_fixup(struct ast_channel *oldchan, struct ast_channel *newchan)
{

	struct dc_pvt *pvt = newchan->tech_pvt;

	if (!pvt) {
		ast_debug(1, "fixup failed, no pvt on newchan\n");
		return -1;
	}

	ast_mutex_lock(&pvt->lock);
	if (pvt->owner == oldchan)
		pvt->owner = newchan;
	ast_mutex_unlock(&pvt->lock);

	return 0;

}

static int dc_devicestate(void *data)
{

	char *device;
	int res = AST_DEVICE_INVALID;
	struct dc_pvt *pvt;

	device = ast_strdupa(S_OR(data, ""));

	ast_debug(1, "Checking device state for device %s\n", device);

	AST_RWLIST_RDLOCK(&devices);
	AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
		if (!strcmp(pvt->id, device))
			break;
	}
	AST_RWLIST_UNLOCK(&devices);

	if (!pvt)
		return res;

	ast_mutex_lock(&pvt->lock);
	if (pvt->connected) {
		if (pvt->owner)
			res = AST_DEVICE_INUSE;
		else
			res = AST_DEVICE_NOT_INUSE;
	}
	ast_mutex_unlock(&pvt->lock);

	return res;

}

/*

	Callback helpers

*/

/*

	do_alignment_detection()

	This routine attempts to detect where we get misaligned audio data from the datacard.

	Sometimes datacards suffer a problem where occasionally they will byte shift the audio stream one byte to the right.
	The result is static or white noise on the inbound (from the adapter) leg of the call.
	This is characterised by a sudden jump in magnitude of the value of the 16 bit samples.

	Here we look at the first 4 48 byte frames. We average the absolute values of each sample in the frame,
	then average the sum of the averages of frames 1, 2, and 3.
	Frame zero is usually zero.
	If the end result > 100, and it usually is if we have the problem, set a flag and compensate by shifting the bytes
	for each subsequent frame during the call.

	If the result is <= 100 then clear the flag so we dont come back in here...

	This seems to work OK....

*/

static void do_alignment_detection(struct dc_pvt *pvt, char *buf, int buflen)
{

	int i;
	short a, *s;
	char *p;

	if (pvt->alignment_detection_triggered) {
		for (i=buflen, p=buf+buflen-1; i>0; i--, p--)
			*p = *(p-1);
		*(p+1) = 0;
		return;
	}

	if (pvt->alignment_count < 4) {
		s = (short *)buf;
		for (i=0, a=0; i<buflen/2; i++) {
			a += *s++;
			a /= i+1;
		}
		pvt->alignment_samples[pvt->alignment_count++] = a;
		return;
	}

	ast_debug(2, "Alignment Detection result is [%-d %-d %-d %-d]\n", pvt->alignment_samples[0], pvt->alignment_samples[1], pvt->alignment_samples[2], pvt->alignment_samples[3]);

	a = abs(pvt->alignment_samples[1]) + abs(pvt->alignment_samples[2]) + abs(pvt->alignment_samples[3]);
	a /= 3;
	if (a > 100) {
		pvt->alignment_detection_triggered = 1;
		ast_debug(1, "Alignment Detection Triggered.\n");
	} else
		pvt->do_alignment_detection = 0;

}

static int dc_queue_control(struct dc_pvt *pvt, enum ast_control_frame_type control)
{
	for (;;) {
		if (pvt->owner) {
			if (ast_channel_trylock(pvt->owner)) {
				DEADLOCK_AVOIDANCE(&pvt->lock);
			} else {
				ast_queue_control(pvt->owner, control);
				ast_channel_unlock(pvt->owner);
				break;
			}
		} else
			break;
	}
	return 0;
}

static int dc_queue_hangup(struct dc_pvt *pvt)
{
	for (;;) {
		if (pvt->owner) {
			if (ast_channel_trylock(pvt->owner)) {
				DEADLOCK_AVOIDANCE(&pvt->lock);
			} else {
				if (pvt->hangupcause != 0) {
					pvt->owner->hangupcause = pvt->hangupcause;
				}
				ast_queue_hangup(pvt->owner);
				ast_channel_unlock(pvt->owner);
				break;
			}
		} else
			break;
	}
	return 0;
}

static int dc_ast_hangup(struct dc_pvt *pvt)
{
	int res = 0;
	for (;;) {
		if (pvt->owner) {
			if (ast_channel_trylock(pvt->owner)) {
				DEADLOCK_AVOIDANCE(&pvt->lock);
			} else {
				res = ast_hangup(pvt->owner);
				/* no need to unlock, ast_hangup() frees the
				 * channel */
				break;
			}
		} else
			break;
	}
	return res;
}

/*

	rfcomm helpers

*/

static int opentty(char *iface)
{
	int fd;
	struct termios term_attr;

	fd = open(iface, O_RDWR | O_NOCTTY);

	if (fd < 0) {
		ast_log(LOG_WARNING, "Unable to open '%s'\n", iface);
		return -1;
	}

	if (tcgetattr(fd, &term_attr) != 0) {
		ast_log(LOG_WARNING, "tcgetattr() failed '%s'\n", iface);
		return -1;
	}

	term_attr.c_cflag = B115200 | CS8 | CREAD;
	term_attr.c_iflag = 0;
	term_attr.c_oflag = 0;
	term_attr.c_lflag = 0;
	term_attr.c_cc[VMIN] = 1;
	term_attr.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSAFLUSH, &term_attr) != 0) {
		ast_log(LOG_WARNING, "tcsetattr() failed '%s'\n", iface);
	}

	return fd;
}

static int dc_data_connect(char *data_tty_str)
{
	return opentty(data_tty_str);
}

static int dc_audio_connect(char *audio_tty_str)
{
	return opentty(audio_tty_str);
}

/*!
 * \brief Write to an rfcomm socket.
 * \param data_socket the socket to write to
 * \param buf the null terminated buffer to write
 *
 * This function will write characters from buf.  The buffer must be null
 * terminated.
 *
 * \retval -1 error
 * \retval 0 success
 */
static int rfcomm_write(int data_socket, char *buf)
{
	return rfcomm_write_full(data_socket, buf, strlen(buf));
}


/*!
 * \brief Write to an rfcomm socket.
 * \param data_socket the socket to write to
 * \param buf the buffer to write
 * \param count the number of characters from the buffer to write
 *
 * This function will write count characters from buf.  It will always write
 * count chars unless it encounters an error.
 *
 * \retval -1 error
 * \retval 0 success
 */
static int rfcomm_write_full(int data_socket, char *buf, size_t count)
{
	char *p = buf;
	ssize_t out_count;

	ast_debug(1, "rfcomm_write() (%d) [%.*s]\n", data_socket, (int) count, buf);
	while (count > 0) {
		if ((out_count = write(data_socket, p, count)) == -1) {
			if (errno==EBADF) ast_debug(1, "rfcomm_write() error: EBADF");
			if (errno==EINVAL) ast_debug(1, "rfcomm_write() error: EINVAL");
			if (errno==EFAULT) ast_debug(1, "rfcomm_write() error: EFAULT");
			if (errno==EPIPE) ast_debug(1, "rfcomm_write() error: EPIPE");
			if (errno==EAGAIN) ast_debug(1, "rfcomm_write() error: EAGAIN");
			if (errno==EINTR) ast_debug(1, "rfcomm_write() error: EINTR");
			if (errno==ENOSPC) ast_debug(1, "rfcomm_write() error: ENOSPC");
			ast_debug(1, "rfcomm_write() error [%d]\n", errno);
			return -1;
		}
		count -= out_count;
		p += out_count;
	}

	return 0;
}

/*!
 * \brief Wait for activity on an rfcomm socket.
 * \param data_socket the socket to watch
 * \param ms a pointer to an int containing a timeout in ms
 * \return zero on timeout and the socket fd (non-zero) otherwise
 * \retval 0 timeout
 */
static int rfcomm_wait(int data_socket, int *ms)
{
	int exception, outfd;
	outfd = ast_waitfor_n_fd(&data_socket, 1, ms, &exception);
	if (outfd < 0)
		outfd = 0;

	return outfd;
}

#ifdef RFCOMM_READ_DEBUG
#define rfcomm_read_debug(c) __rfcomm_read_debug(c)
static void __rfcomm_read_debug(char c)
{
	if (c == '\r')
		ast_debug(2, "rfcomm_read: \\r\n");
	else if (c == '\n')
		ast_debug(2, "rfcomm_read: \\n\n");
	else
		ast_debug(2, "rfcomm_read: %c\n", c);
}
#else
#define rfcomm_read_debug(c)
#endif

/*!
 * \brief Append the given character to the given buffer and increase the
 * in_count.
 */
static void inline rfcomm_append_buf(char **buf, size_t count, size_t *in_count, char c)
{
	if (*in_count < count) {
		(*in_count)++;
		*(*buf)++ = c;
	}
}

/*!
 * \brief Read a character from the given stream and check if it matches what
 * we expected.
 */
static int rfcomm_read_and_expect_char(int data_socket, char *result, char expected)
{
	int res;
	char c;

	if (!result)
		result = &c;

	if ((res = read(data_socket, result, 1)) < 1) {
		return res;
	}
	rfcomm_read_debug(*result);

	if (*result != expected) {
		return -2;
	}

	return 1;
}

/*!
 * \brief Read a character from the given stream and append it to the given
 * buffer if it matches the expected character.
 */
static int rfcomm_read_and_append_char(int data_socket, char **buf, size_t count, size_t *in_count, char *result, char expected)
{
	int res;
	char c;

	if (!result)
		result = &c;

	if ((res = rfcomm_read_and_expect_char(data_socket, result, expected)) < 1) {
		return res;
	}

	rfcomm_append_buf(buf, count, in_count, *result);
	return 1;
}

/*!
 * \brief Read until '\r\n'.
 * This function consumes the '\r\n' but does not add it to buf.
 */
static int rfcomm_read_until_crlf(int data_socket, char **buf, size_t count, size_t *in_count)
{
	int res;
	char c;

	while ((res = read(data_socket, &c, 1)) == 1) {
		rfcomm_read_debug(c);

		// Fix: The Huawei sticks do not terminate this command with a \r\n
		// So we have to handle this command separately 
		if (*in_count >= 7 && !strncmp(*buf - *in_count, "+CSSI: ", 7)) {
			rfcomm_append_buf(buf, count, in_count, c);
			return 1;
		}

		// Fix: The Huawei sticks do not terminate this command with a \r\n
		// So we have to handle this command separately
		if (*in_count >= 7 && !strncmp(*buf - *in_count, "+CSSU: ", 7)) {
			rfcomm_append_buf(buf, count, in_count, c);
			return 1;
		}

		if (c == '\r') {
			if ((res = rfcomm_read_and_expect_char(data_socket, &c, '\n')) == 1) {
				break;
			} else if (res == -2) {
				rfcomm_append_buf(buf, count, in_count, '\r');
			} else {
				rfcomm_append_buf(buf, count, in_count, '\r');
				break;
			}
		}

		rfcomm_append_buf(buf, count, in_count, c);
	}
	return res;
}

/*!
 * \brief Read the remainder of an AT SMS prompt.
 * \note the entire parsed string is '\r\n> '
 *
 * By the time this function is executed, only a ' ' is left to read.
 */
static int rfcomm_read_sms_prompt(int data_socket, char **buf, size_t count, size_t *in_count)
{
	int res;
	if ((res = rfcomm_read_and_append_char(data_socket, buf, count, in_count, NULL, ' ')) < 1)
	       goto e_return;

	return 1;

e_return:
	ast_log(LOG_ERROR, "error parsing SMS prompt on rfcomm socket\n");
	return res;
}

/*!
 * \brief Read and AT result code.
 * \note the entire parsed string is '\r\n<result code>\r\n'
 */
static int rfcomm_read_result(int data_socket, char **buf, size_t count, size_t *in_count)
{
	int res;
	char c;

	if ((res = rfcomm_read_and_expect_char(data_socket, &c, '\n')) < 1) {
		goto e_return;
	}

	if ((res = rfcomm_read_and_append_char(data_socket, buf, count, in_count, &c, '>')) == 1) {
		return rfcomm_read_sms_prompt(data_socket, buf, count, in_count);
	} else if (res != -2) {
		goto e_return;
	}

	rfcomm_append_buf(buf, count, in_count, c);
	res = rfcomm_read_until_crlf(data_socket, buf, count, in_count);

	if (res != 1)
		return res;

	/* check for CMGR, which contains an embedded \r\n */
	if (*in_count >= 5 && !strncmp(*buf - *in_count, "+CMGR", 5)) {
		rfcomm_append_buf(buf, count, in_count, '\r');
		rfcomm_append_buf(buf, count, in_count, '\n');
		return rfcomm_read_until_crlf(data_socket, buf, count, in_count);
	}

	return 1;

e_return:
	ast_log(LOG_ERROR, "error parsing AT result on rfcomm socket.\n");
	return res;
}

/*!
 * \brief Read the remainder of an AT command.
 * \note the entire parsed string is '<at command>\r'
 */
static int rfcomm_read_command(int data_socket, char **buf, size_t count, size_t *in_count)
{
	int res;
	char c;

	while ((res = read(data_socket, &c, 1)) == 1) {
		rfcomm_read_debug(c);
		/* stop when we get to '\r' */
		if (c == '\r')
			break;

		rfcomm_append_buf(buf, count, in_count, c);
	}
	return res;
}

/*!
 * \brief Read one Hayes AT message from an rfcomm socket.
 * \param data_socket the rfcomm socket to read from
 * \param buf the buffer to store the result in
 * \param count the size of the buffer or the maximum number of characters to read
 *
 * Here we need to read complete Hayes AT messages.  The AT message formats we
 * support are listed below.
 *
 * \verbatim
 * \r\n<result code>\r\n
 * <at command>\r
 * \r\n> 
 * \endverbatim
 *
 * These formats correspond to AT result codes, AT commands, and the AT SMS
 * prompt respectively.  When messages are read the leading and trailing '\r'
 * and '\n' characters are discarded.  If the given buffer is not large enough
 * to hold the response, what does not fit in the buffer will be dropped.
 *
 * \note The rfcomm connection to the device is asynchronous, so there is no
 * guarantee that responses will be returned in a single read() call. We handle
 * this by blocking until we can read an entire response.
 *
 * \retval 0 end of file
 * \retval -1 read error
 * \retval -2 parse error
 * \retval other the number of characters added to buf
 */
static ssize_t rfcomm_read(int data_socket, char *buf, size_t count)
{
	ssize_t res;
	size_t in_count = 0;
	char c;

	if ((res = rfcomm_read_and_expect_char(data_socket, &c, '\r')) == 1) {
		res = rfcomm_read_result(data_socket, &buf, count, &in_count);
	} else if (res == -2) {
		rfcomm_append_buf(&buf, count, &in_count, c);
		res = rfcomm_read_command(data_socket, &buf, count, &in_count);
	}

	if (res < 1)
		return res;
	else
		return in_count;
}

/*

	audio and callbacks

*/

static int audio_write(int s, char *buf, int len)
{

	int r;

	if (s == -1) {
		ast_debug(3, "audio_write() not ready\n");
		return 0;
	}

	ast_debug(3, "audio_write()\n");

	r = write(s, buf, len);
	if (r == -1) {
		ast_debug(3, "audio write error %d\n", errno);
		/*
		if (errno==EBADF) ast_debug(1, "audio_write() error: EBADF\n");
                if (errno==EINVAL) ast_debug(1, "audio_write() error: EINVAL\n");
                if (errno==EFAULT) ast_debug(1, "audio_write() error: EFAULT\n");
                if (errno==EPIPE) ast_debug(1, "audio_write() error: EPIPE\n");
                if (errno==EAGAIN) ast_debug(1, "audio_write() error: EAGAIN\n");
                if (errno==EINTR) ast_debug(1, "audio_write() error: EINTR\n");
                if (errno==ENOSPC) ast_debug(1, "audio_write() error: ENOSPC\n");
		*/
                ast_debug(1, "audio_write() error [%d]\n", errno);
		return 0;
	}

	return 1;

}

/*
 * Hayes AT command helpers.
 */

/*!
 * \brief Match the given buffer with the given prefix.
 * \param buf the buffer to match
 * \param prefix the prefix to match
 */
static int at_match_prefix(char *buf, char *prefix)
{
	return !strncmp(buf, prefix, strlen(prefix));
}

/*!
 * \brief Read an AT message and clasify it.
 * \param data_socket an rfcomm socket
 * \param buf the buffer to store the result in
 * \param count the size of the buffer or the maximum number of characters to read
 * \return the type of message received, in addition buf will contain the
 * message received and will be null terminated
 * \see at_read()
 */
static at_message_t at_read_full(int data_socket, char *buf, size_t count)
{
	ssize_t s;
	if ((s = rfcomm_read(data_socket, buf, count - 1)) < 1)
		return s;
	buf[s] = '\0';

	if (!strcmp("OK", buf)) {
		return AT_OK;
	} else if (!strcmp("ERROR", buf)) {
		return AT_ERROR;
	} else if (!strcmp("COMMAND NOT SUPPORT", buf)) {
		return AT_ERROR;
	} else if (!strcmp("RING", buf)) {
		return AT_RING;
	} else if (!strcmp("AT+CKPD=200", buf)) {
		return AT_CKPD;
	} else if (!strcmp("> ", buf)) {
		return AT_SMS_PROMPT;
	} else if (at_match_prefix(buf, "+CMTI:")) {
		return AT_CMTI;
	} else if (at_match_prefix(buf, "+CLIP:")) {
		return AT_CLIP;
	} else if (at_match_prefix(buf, "+CMGR:")) {
		return AT_CMGR;
	} else if (at_match_prefix(buf, "+VGM:")) {
		return AT_VGM;
	} else if (at_match_prefix(buf, "+VGS:")) {
		return AT_VGS;
	} else if (at_match_prefix(buf, "+CMS ERROR:")) {
		return AT_CMS_ERROR;
	} else if (at_match_prefix(buf, "AT+VGM=")) {
		return AT_VGM;
	} else if (at_match_prefix(buf, "AT+VGS=")) {
		return AT_VGS;
	} else if (at_match_prefix(buf, "+CUSD:")) {
		return AT_CUSD;
	} else if (at_match_prefix(buf, "BUSY")) {
		return AT_BUSY;
	} else if (at_match_prefix(buf, "NO DIALTONE")) {
		return AT_NO_DIALTONE;
	} else if (at_match_prefix(buf, "NO CARRIER")) {
		return AT_NO_CARRIER;
	} else if (at_match_prefix(buf, "^CONN:")) {
		return AT_CONN;
	} else if (at_match_prefix(buf, "^CEND:")) {
		return AT_CEND;
	} else if (at_match_prefix(buf, "^CONF:")) {
		return AT_CONF;
	} else if (at_match_prefix(buf, "^ORIG:")) {
		return AT_ORIG;
	} else if (at_match_prefix(buf, "^RSSI:")) {
		return AT_RSSI;
	} else if (at_match_prefix(buf, "^BOOT:")) {
		return AT_BOOT;
	} else if (at_match_prefix(buf, "+CSSN:")) {
		return AT_CSSN;
	} else if (at_match_prefix(buf, "+CSSI:")) {
		return AT_CSSI;
	} else if (at_match_prefix(buf, "+CSSU:")) {
		return AT_CSSU;
	} else if (at_match_prefix(buf, "+CPIN:")) {
		return AT_CPIN;
	} else if (at_match_prefix(buf, "^DDSETEX:")) {
		return AT_DDSETEX;
	} else if (at_match_prefix(buf, "^CVOICE:")) {
		return AT_CVOICE;
	} else if (at_match_prefix(buf, "^MODE:")) {
		return AT_MODE;
	} else if (at_match_prefix(buf, "+CPMS:")) {
		return AT_CPMS;
	} else if (at_match_prefix(buf, "^SIMST:")) {
		return AT_SIMST;
	} else if (at_match_prefix(buf, "^SRVST:")) {
		return AT_SRVST;
	} else {
		return AT_UNKNOWN;
	}
}

/*!
 * \brief Get the string representation of the given AT message.
 * \param msg the message to process
 * \return a string describing the given message
 */
static inline const char *at_msg2str(at_message_t msg)
{
	switch (msg) {
	/* errors */
	case AT_PARSE_ERROR:
		return "PARSE ERROR";
	case AT_READ_ERROR:
		return "READ ERROR";
	default:
	case AT_UNKNOWN:
		return "UNKNOWN";
	/* at responses */
	case AT_OK:
		return "OK";
	case AT_ERROR:
		return "ERROR";
	case AT_RING:
		return "RING";
	case AT_CLIP:
		return "AT+CLIP";
	case AT_CMTI:
		return "AT+CMTI";
	case AT_CMGR:
		return "AT+CMGR";
	case AT_SMS_PROMPT:
		return "SMS PROMPT";
	case AT_CMS_ERROR:
		return "+CMS ERROR";
	case AT_BUSY:
		return "BUSY";
	case AT_NO_DIALTONE:
		return "NO DIALTONE";
	case AT_NO_CARRIER:
		return "NO CARRIER";
	/* at commands */
	case AT_A:
		return "ATA";
	case AT_D:
		return "ATD";
	case AT_E0:
		return "ATE0";
	case AT_DDSETEX:
		return "AT^DDSETEX";
	case AT_CVOICE:
		return "AT^CVOICE";
	case AT_CONN:
		return "^CONN:";
	case AT_CEND:
		return "^CEND:";
	case AT_CONF:
		return "^CONF:";
	case AT_ORIG:
		return "^ORIG:";
	case AT_RSSI:
		return "^RSSI:";
	case AT_BOOT:
		return "^BOOT:";
	case AT_CSSN:
		return "AT+CSSN";
	case AT_CSSI:
		return "+CSSI:";
	case AT_CSSU:
		return "+CSSU:";
	case AT_CHUP:
		return "AT+CHUP";
	case AT_CKPD:
		return "AT+CKPD";
	case AT_CMGS:
		return "AT+CMGS";
	case AT_VGM:
		return "AT+VGM";
	case AT_VGS:
		return "AT+VGS";
	case AT_VTS:
		return "AT+VTS";
	case AT_CMGF:
		return "AT+CMGF";
	case AT_CNMI:
		return "AT+CNMI";
	case AT_CUSD:
		return "AT+CUSD";
	case AT_CPIN:
		return "AT+CPIN";
	case AT_MODE:
		return "AT^MODE";
	case AT_CLVL:
		return "AT+CLVL";
	case AT_CPMS:
		return "AT+CPMS";
	}
}


/*
 * datacard helpers
 */

/*!
 * \brief Parse a CLIP event.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * @note buf will be modified when the CID string is parsed
 * \return NULL on error (parse error) or a pointer to the caller id
 * inforamtion in buf
 * success
 */
static char *dc_parse_clip(struct dc_pvt *pvt, char *buf)
{
	int i, state;
	char *clip;
	size_t s;

	/* parse clip info in the following format:
	 * +CLIP: "123456789",128,...
	 */
	state = 0;
	s = strlen(buf);
	for (i = 0; i < s && state != 3; i++) {
		switch (state) {
		case 0: /* search for start of the number (") */
			if (buf[i] == '"') {
				state++;
			}
			break;
		case 1: /* mark the number */
			clip = &buf[i];
			state++;
			/* fall through */
		case 2: /* search for the end of the number (") */
			if (buf[i] == '"') {
				buf[i] = '\0';
				state++;
			}
			break;
		}
	}

	if (state != 3) {
		return NULL;
	}

	return clip;
}

/*!
 * \brief Parse a CMTI notification.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * @note buf will be modified when the CMTI message is parsed
 * \return -1 on error (parse error) or the index of the new sms message
 */
static int dc_parse_cmti(struct dc_pvt *pvt, char *buf)
{
	int index = -1;

	/* parse cmti info in the following format:
	 * +CMTI: <mem>,<index> 
	 */
	if (!sscanf(buf, "+CMTI: %*[^,],%d", &index)) {
		ast_debug(2, "[%s] error parsing CMTI event '%s'\n", pvt->id, buf);
		return -1;
	}

	return index;
}

/*!
 * \brief Parse a CMGR message.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * \param from_number a pointer to a char pointer which will store the from
 * number
 * \param text a pointer to a char pointer which will store the message text
 * @note buf will be modified when the CMGR message is parsed
 * \retval -1 parse error
 * \retval 0 success
 */
static int dc_parse_cmgr(struct dc_pvt *pvt, char *buf, char **from_number, char **text)
{
	int i, state;
	size_t s;

	/* parse cmgr info in the following format:
	 * +CMGR: <msg status>,"+123456789",...\r\n
	 * <message text>
	 */
	state = 0;
	s = strlen(buf);
	for (i = 0; i < s && s != 6; i++) {
		switch (state) {
		case 0: /* search for start of the number section (,) */
			if (buf[i] == ',') {
				state++;
			}
			break;
		case 1: /* find the opening quote (") */
			if (buf[i] == '"') {
				state++;
			}
		case 2: /* mark the start of the number */
			if (from_number) {
				*from_number = &buf[i];
				state++;
			}
			/* fall through */
		case 3: /* search for the end of the number (") */
			if (buf[i] == '"') {
				buf[i] = '\0';
				state++;
			}
			break;
		case 4: /* search for the start of the message text (\n) */
			if (buf[i] == '\n') {
				state++;
			}
			break;
		case 5: /* mark the start of the message text */
			if (text) {
				*text = &buf[i];
				state++;
			}
			break;
		}
	}

	if (state != 6) {
		return -1;
	}

	return 0;
}

 /*!
 * \brief Parse a CUSD answer.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * @note buf will be modified when the CUSD string is parsed
 * \return NULL on error (parse error) or a pointer to the cusd message
 * inforamtion in buf
 * success
 */
static char *dc_parse_cusd(struct dc_pvt *pvt, char *buf)
{
	int i, state, message_start, message_end;
	char *cusd;
	size_t s;

	/* parse cusd message in the following format:
	 * +CUSD: 0,"100,00 EURO, valid till 01.01.2010, you are using tariff "Mega Tariff". More informations *111#."
	 */
	state = 0;
	message_start = 0;
	message_end = 0;
	s = strlen(buf);

	/* Find the start of the message (") */
	for (i = 0; i < s; i++) {
		if (buf[i] == '"') {
			message_start = i + 1;
			break;
		}
	}

	if (message_start == 0 || message_start >= s) {
		return NULL;
	}

	/* Find the end of the message (") */
	for (i = s; i > 0; i--) {
		if (buf[i] == '"') {
			message_end = i;
			break;
		}
	}

	if (message_end == 0) {
		return NULL;
	}

	if (message_start >= message_end) {
		return NULL;
	}

	cusd = &buf[message_start];
	buf[message_end] = '\0';

	return cusd;
}

// FIXME: Finish parsing
/*!
 * \brief Parse a CPIN notification.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * \return 2 if PUK required
 * \return 1 if PIN required
 * \return 0 if no PIN required
 * \return -1 on error (parse error) or card lock
 */
static int dc_parse_cpin(struct dc_pvt *pvt, char *buf)
{
	if (strstr(buf, "READY")) return 0;
	if (strstr(buf, "SIM PIN"))
	{
		ast_log(LOG_ERROR, "Datacard %s needs PIN code!\n", pvt->id);
		return 1;
	}
	if (strstr(buf, "SIM PUK")) {
		ast_log(LOG_ERROR, "Datacard %s needs PUK code!\n", pvt->id);
		return 2;
	}

	ast_log(LOG_ERROR, "Error parsing +CPIN message on Datacard: %s %s\n", pvt->id, buf);
	return -1;
}

/*!
 * \brief Parse a ^RSSI notification.
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * \return -1 on error (parse error) or the rssi value
 */
static int dc_parse_rssi(struct dc_pvt *pvt, char *buf)
{
	int rssi = -1;

	/* parse RSSI info in the following format:
	 * ^RSSI:<rssi>
	 */
	if (!sscanf(buf, "^RSSI:%d", &rssi)) {
		ast_debug(2, "[%s] error parsing RSSI event '%s'\n", pvt->id, buf);
		return -1;
	}

	return rssi;
}

/*!
 * \brief Parse a ^MODE notification (link mode).
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * \return -1 on error (parse error) or the the link mode value
 */
static int dc_parse_linkmode(struct dc_pvt *pvt, char *buf)
{
	int mode = -1;
	int submode = -1;

	/* parse RSSI info in the following format:
	 * ^MODE:<mode>,<submode>
	 */
	if (!sscanf(buf, "^MODE:%d,%d", &mode, &submode)) {
		ast_debug(2, "[%s] error parsing MODE event '%s'\n", pvt->id, buf);
		return -1;
	}

	return mode;
}

/*!
 * \brief Parse a ^MODE notification (link sub mode).
 * \param pvt an dc_pvt struct
 * \param buf the buffer to parse (null terminated)
 * \return -1 on error (parse error) or the link sub mode value
 */
static int dc_parse_linksubmode(struct dc_pvt *pvt, char *buf)
{
	int mode = -1;
	int submode = -1;

	/* parse RSSI info in the following format:
	 * ^MODE:<mode>,<submode>
	 */
	if (!sscanf(buf, "^MODE:%d,%d", &mode, &submode)) {
		ast_debug(2, "[%s] error parsing MODE event '%s'\n", pvt->id, buf);
		return -1;
	}

	return submode;
}



/*!
 * \brief Send the ATE0 command.
 * \param pvt an dc_pvt struct
 */
static int dc_send_ate0(struct dc_pvt *pvt)
{
	return rfcomm_write(pvt->data_socket, "ATE0\r");
}

/*!
 *  * \brief Manage Supplementary Service Notification.
 *  * \param pvt an dc_pvt struct
 *  * \param cssi the value to send (0 = disabled, 1 = enabled)
 *  * \param cssu the value to send (0 = disabled, 1 = enabled)
 *  */
static int dc_send_cssn(struct dc_pvt *pvt, int cssi, int cssu)
{
	char cmd[32];
	snprintf(cmd, sizeof(cmd), "AT+CSSN=%d,%d\r", cssi, cssu);
	return rfcomm_write(pvt->data_socket, cmd);
}

#if 0
/*!
 * \brief Send the current microphone gain level.
 * \param pvt an dc_pvt struct
 * \param value the value to send (must be between 0 and 15)
 */
static int dc_send_vgm(struct dc_pvt *pvt, int value)
{
	char cmd[32];
	snprintf(cmd, sizeof(cmd), "AT+VGM=%d\r", value);
	return rfcomm_write(pvt->data_socket, cmd);
}
#endif

/*!
 * \brief Send AT+CPIN=? to ask the datacard if a pin code is required
 * \param pvt an dc_pvt struct
 */
static int dc_send_cpin_test(struct dc_pvt *pvt)
{
       char cmd[32];
       snprintf(cmd, sizeof(cmd), "AT+CPIN?\r");
       return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Enable or disable calling line identification.
 * \param pvt an dc_pvt struct
 * \param status enable or disable calling line identification (should be 1 or
 * 0)
 */
static int dc_send_clip(struct dc_pvt *pvt, int status)
{
	char cmd[32];
	snprintf(cmd, sizeof(cmd), "AT+CLIP=%d\r", status ? 1 : 0);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Enable transmitting of audio to the debug port (tty)
 * \param pvt an dc_pvt struct
 */
static int dc_send_ddsetex(struct dc_pvt *pvt)
{
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "AT^DDSETEX=2\r");
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Check device for audio capabilities
 * \param pvt an dc_pvt struct
 */
static int dc_send_cvoice_test(struct dc_pvt *pvt)
{
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "AT^CVOICE?\r");
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Set storage location for incoming SMS
 * \param pvt an dc_pvt struct
 */
static int dc_send_cpms(struct dc_pvt *pvt)
{
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "AT+CPMS=\"SM\",\"SM\",\"SM\"\r");
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Send a DTMF command.
 * \param pvt an dc_pvt struct
 * \param digit the dtmf digit to send
 * \return the result of rfcomm_write() or -1 on an invalid digit being sent
 */
static int dc_send_dtmf(struct dc_pvt *pvt, char digit)
{
	char cmd[10];

	switch(digit) {
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
		snprintf(cmd, sizeof(cmd), "AT+VTS=%c\r", digit);
		return rfcomm_write(pvt->data_socket, cmd);
	default:
		return -1;
	}
}

/*!
 * \brief Set the SMS mode.
 * \param pvt an dc_pvt struct
 * \param mode the sms mode (0 = PDU, 1 = Text)
 */
static int dc_send_cmgf(struct dc_pvt *pvt, int mode)
{
	char cmd[32];
	snprintf(cmd, sizeof(cmd), "AT+CMGF=%d\r", mode);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Setup SMS new message indication.
 * \param pvt an dc_pvt struct
 */
static int dc_send_cnmi(struct dc_pvt *pvt)
{
	return rfcomm_write(pvt->data_socket, "AT+CNMI=2,1,0,0,0\r");
}

/*!
 * \brief Read an SMS message.
 * \param pvt an dc_pvt struct
 * \param index the location of the requested message
 */
static int dc_send_cmgr(struct dc_pvt *pvt, int index)
{
	char cmd[32];
	snprintf(cmd, sizeof(cmd), "AT+CMGR=%d\r", index);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Start sending an SMS message.
 * \param pvt an dc_pvt struct
 * \param number the destination of the message
 */
static int dc_send_cmgs(struct dc_pvt *pvt, const char *number)
{
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "AT+CMGS=\"%s\"\r", number);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Send the text of an SMS message.
 * \param pvt an dc_pvt struct
 * \param message the text of the message
 */
static int dc_send_sms_text(struct dc_pvt *pvt, const char *message)
{
	char cmd[162];
	snprintf(cmd, sizeof(cmd), "%.160s\x1a", message);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Send AT+CHUP.
 * \param pvt an dc_pvt struct
 */
static int dc_send_chup(struct dc_pvt *pvt)
{
	return rfcomm_write(pvt->data_socket, "AT+CHUP\r");
}

/*!
 * \brief Send ATD.
 * \param pvt an dc_pvt struct
 * \param number the number to send
 */
static int dc_send_atd(struct dc_pvt *pvt, const char *number)
{
	char cmd[64];
	snprintf(cmd, sizeof(cmd), "ATD%s;\r", number);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Send ATA.
 * \param pvt an dc_pvt struct
 */
static int dc_send_ata(struct dc_pvt *pvt)
{
	return rfcomm_write(pvt->data_socket, "ATA\r");
}

/*!
 * \brief Send AT+CUSD.
 * \param pvt an dc_pvt struct
 * \param code the CUSD code to send
 */
static int dc_send_cusd(struct dc_pvt *pvt, const char *code)
{
	char cmd[128];
	snprintf(cmd, sizeof(cmd), "AT+CUSD=1,\"%s\",15\r", code);
	return rfcomm_write(pvt->data_socket, cmd);
}

/*!
 * \brief Send AT+CLVL.
 * \param pvt an dc_pvt struct
 * \param volume level to send
 */
static int dc_send_clvl(struct dc_pvt *pvt, int level)
{
	char cmd[16];
	snprintf(cmd, sizeof(cmd), "AT+CLVL=%d\r", level);
	return rfcomm_write(pvt->data_socket, cmd);
}


/*
 * message queue functions
 */

/*!
 * \brief Add an item to the back of the queue.
 * \param pvt a dc_pvt structure
 * \param expect the msg we expect to recieve
 * \param response_to the message that was sent to generate the expected
 * response
 */
static int msg_queue_push(struct dc_pvt *pvt, at_message_t expect, at_message_t response_to)
{
	struct msg_queue_entry *msg;
	if (!(msg = ast_calloc(1, sizeof(*msg)))) {
		return -1;
	}
	msg->expected = expect;
	msg->response_to = response_to;

	AST_LIST_INSERT_TAIL(&pvt->msg_queue, msg, entry);
	return 0;
}

/*!
 * \brief Add an item to the back of the queue with data.
 * \param pvt a dc_pvt structure
 * \param expect the msg we expect to recieve
 * \param response_to the message that was sent to generate the expected
 * response
 * \param data data associated with this message, it will be freed when the
 * message is freed
 */
static int msg_queue_push_data(struct dc_pvt *pvt, at_message_t expect, at_message_t response_to, void *data)
{
	struct msg_queue_entry *msg;
	if (!(msg = ast_calloc(1, sizeof(*msg)))) {
		return -1;
	}
	msg->expected = expect;
	msg->response_to = response_to;
	msg->data = data;

	AST_LIST_INSERT_TAIL(&pvt->msg_queue, msg, entry);
	return 0;
}

/*!
 * \brief Remove an item from the front of the queue.
 * \param pvt a dc_pvt structure
 * \return a pointer to the removed item
 */
static struct msg_queue_entry *msg_queue_pop(struct dc_pvt *pvt)
{
	return AST_LIST_REMOVE_HEAD(&pvt->msg_queue, entry);
}

/*!
 * \brief Remove an item from the front of the queue, and free it.
 * \param pvt a dc_pvt structure
 */
static void msg_queue_free_and_pop(struct dc_pvt *pvt)
{
	struct msg_queue_entry *msg;
	if ((msg = msg_queue_pop(pvt))) {
		if (msg->data)
			ast_free(msg->data);
		ast_free(msg);
	}
}

/*!
 * \brief Remove all itmes from the queue and free them.
 * \param pvt a dc_pvt structure
 */
static void msg_queue_flush(struct dc_pvt *pvt)
{
	struct msg_queue_entry *msg;
	while ((msg = msg_queue_head(pvt)))
		msg_queue_free_and_pop(pvt);
}

/*!
 * \brief Get the head of a queue.
 * \param pvt a dc_pvt structure
 * \return a pointer to the head of the given msg queue
 */
static struct msg_queue_entry *msg_queue_head(struct dc_pvt *pvt)
{
	return AST_LIST_FIRST(&pvt->msg_queue);
}



/*

	Thread routines

*/

/*!
 * \brief Handle OK AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_ok(struct dc_pvt *pvt, char *buf)
{
		struct msg_queue_entry *entry;
		if ((entry = msg_queue_head(pvt)) && entry->expected == AT_OK) {
			switch (entry->response_to) {
		
		/* initilization stuff */
		case AT_E0:
			if (dc_send_cpin_test(pvt) || msg_queue_push(pvt, AT_OK, AT_CPIN)) {
				ast_debug(1, "[%s] Error asking datacard for PIN.\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CPIN:
			if (dc_send_cvoice_test(pvt) || msg_queue_push(pvt, AT_OK, AT_CVOICE)) {
				ast_debug(1, "[%s] Error checking voice capabilities.\n", pvt->id);
				goto e_return;
			}
		break;
		case AT_CVOICE:
			pvt->has_voice = 1;
			ast_debug(1, "[%s] Datacard has voice support.\n", pvt->id);
			if (dc_send_clvl(pvt,1) || msg_queue_push(pvt, AT_OK, AT_CLVL)) {
				ast_debug(1, "[%s] Error syncronizing audio level (part1/2)\n", pvt->id);
				goto e_return;
			}
		break;
		case AT_CLVL:
			if (pvt->volume_synchronized == 0) {
				pvt->volume_synchronized=1;
				if (dc_send_clvl(pvt,5) || msg_queue_push(pvt, AT_OK, AT_CLVL)) {
					ast_debug(1, "[%s] Error syncronizing audio level (part2/2).\n", pvt->id);
					goto e_return;
				}
			}
			else {
				if (dc_send_clip(pvt, 1) || msg_queue_push(pvt, AT_OK, AT_CLIP)) {
					ast_debug(1, "[%s] Error enabling calling line notification.\n", pvt->id);
					goto e_return;
				}
			}
			break;
		case AT_CLIP:
			ast_debug(1, "[%s] caling line indication enabled\n", pvt->id);
			if (dc_send_cssn(pvt,1,1) || msg_queue_push(pvt, AT_OK, AT_CSSN)) {
				ast_debug(1, "[%s] Error activating Supplementary Service Notification.\n", pvt->id);
				goto e_return;
			}

			pvt->timeout = -1;
			pvt->initialized = 1;
			ast_verb(3, "Datacard %s initialized and ready.\n", pvt->id);

			break;
		case AT_CSSN:
			ast_debug(1, "[%s] Supplementary Service Notification enabled successful\n", pvt->id);

			/* set the SMS operating mode to text mode */
			if (dc_send_cmgf(pvt, 1) || msg_queue_push(pvt, AT_OK, AT_CMGF)) {
				ast_debug(1, "[%s] error setting CMGF\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CMGF:
			ast_debug(1, "[%s] sms text mode enabled\n", pvt->id);
			/* set SMS storage location */
			if (dc_send_cpms(pvt) || msg_queue_push(pvt, AT_OK, AT_CPMS)) {
				ast_debug(1, "[%s] error setting CPMS\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CPMS:
			/* turn on SMS new message indication */
			if (dc_send_cnmi(pvt) || msg_queue_push(pvt, AT_OK, AT_CNMI)) {
				ast_debug(1, "[%s] error setting CNMI\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CNMI:
			ast_debug(1, "[%s] sms new message indication enabled\n", pvt->id);
			ast_debug(1, "[%s] Datacard has sms support.\n", pvt->id);
			pvt->has_sms = 1;
			break;

		/* end initilization stuff */

		case AT_A:
			ast_debug(1, "[%s] answer sent successfully\n", pvt->id);
			pvt->needchup = 1;

			if (dc_send_ddsetex(pvt) || msg_queue_push(pvt, AT_OK, AT_DDSETEX)) {
				ast_debug(1, "[%s] error sending AT^DDSETEX\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_D:
			ast_debug(1, "[%s] dial sent successfully\n", pvt->id);
			dc_queue_control(pvt, AST_CONTROL_PROGRESS);

			if (dc_send_ddsetex(pvt) || msg_queue_push(pvt, AT_OK, AT_DDSETEX)) {
				ast_debug(1, "[%s] error sending AT^DDSETEX\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_DDSETEX:
			ast_debug(1, "[%s] AT^DDSETEX sent successfully\n", pvt->id);
			break;
		case AT_CHUP:
			ast_debug(1, "[%s] successful hangup\n", pvt->id);
			break;
		case AT_CMGR:
			ast_debug(1, "[%s] successfully read sms message\n", pvt->id);
			pvt->incoming_sms = 0;
			break;
		case AT_CMGS:
			ast_debug(1, "[%s] successfully sent sms message\n", pvt->id);
			pvt->outgoing_sms = 0;
			break;
		case AT_VTS:
			ast_debug(1, "[%s] digit sent successfully\n", pvt->id);
			break;
		case AT_CUSD:
			ast_debug(1, "[%s] CUSD code sent successfully\n", pvt->id);
			break;
		case AT_UNKNOWN:
		default:
			ast_debug(1, "[%s] recieved OK for unhandled request: %s\n", pvt->id, at_msg2str(entry->response_to));
			break;
		}
		msg_queue_free_and_pop(pvt);
	} else if (entry) {
		ast_debug(1, "[%s] recieved AT message 'OK' when expecting %s, ignoring\n", pvt->id, at_msg2str(entry->expected));
	} else {
		ast_debug(1, "[%s] recieved unexpected AT message 'OK'\n", pvt->id);
	}
	return 0;

e_return:
	msg_queue_free_and_pop(pvt);
	return -1;
}

/*!
 * \brief Handle ERROR AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_error(struct dc_pvt *pvt, char *buf)
{
	struct msg_queue_entry *entry;
	if ((entry = msg_queue_head(pvt))
			&& (entry->expected == AT_OK
			|| entry->expected == AT_ERROR
			|| entry->expected == AT_CMS_ERROR
			|| entry->expected == AT_CMGR
			|| entry->expected == AT_SMS_PROMPT)) {
		switch (entry->response_to) {

		/* initilization stuff */
		case AT_E0:
			ast_debug(1, "[%s] ATE0 failed\n", pvt->id);
			goto e_return;
			
			/* this is not a fatal error, let's continue with initilization */
			/*
			if (dc_send_clip(pvt, 1) || msg_queue_push(pvt, AT_OK, AT_CLIP)) {
				ast_debug(1, "[%s] error enabling calling line notification\n", pvt->id);
				goto e_return;
			}
			break;
			*/
		case AT_CPIN:
			ast_debug(1, "[%s] error checking PIN state\n", pvt->id);
			goto e_return;
		case AT_CVOICE:
			ast_debug(1, "[%s] Datacard has NO voice support.\n", pvt->id);
			/* this is not a fatal error, let's continue with initilization */
			pvt->has_voice = 0;
			if (dc_send_clvl(pvt,1) || msg_queue_push(pvt, AT_OK, AT_CLVL)) {
				ast_debug(1, "[%s] error syncronizing audio level (part1/2)\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CLVL:
			ast_debug(1, "[%s] error syncronizing audio level\n", pvt->id);
			/* this is not a fatal error, let's continue with initilization */
			pvt->volume_synchronized == 0;
			if (dc_send_clip(pvt, 1) || msg_queue_push(pvt, AT_OK, AT_CLIP)) {
				ast_debug(1, "[%s] Error enabling calling line notification.\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CLIP:
			ast_debug(1, "[%s] error enabling calling line indication\n", pvt->id);
			goto e_return;
		case AT_CSSN:
			ast_debug(1, "[%s] error Supplementary Service Notification activation failed\n", pvt->id);

			/* this is not a fatal error, let's continue with initilization */

			/* set the SMS operating mode to text mode */
			if (dc_send_cmgf(pvt, 1) || msg_queue_push(pvt, AT_OK, AT_CMGF)) {
				ast_debug(1, "[%s] error setting CMGF\n", pvt->id);
				goto e_return;
			}
			break;
		case AT_CMGF:
			ast_debug(1, "[%s] error enableing text-mode SMS (CMGF)\n", pvt->id);
			ast_debug(1, "[%s] no SMS support\n", pvt->id);
			break;
		case AT_CPMS:
			ast_debug(1, "[%s] error setting sms storage location (CPMS)\n", pvt->id);
			ast_debug(1, "[%s] no SMS support\n", pvt->id);
			break;
		case AT_CNMI:
			ast_debug(1, "[%s] error setting sms notifications (CNMI)\n", pvt->id);
			ast_debug(1, "[%s] no SMS support\n", pvt->id);
			break;

		/* end initilization stuff */

		case AT_A:
			ast_debug(1, "[%s] answer failed\n", pvt->id);
			dc_queue_hangup(pvt);
			break;
		case AT_D:
			ast_debug(1, "[%s] dial failed\n", pvt->id);
			pvt->needchup = 0;
			dc_queue_control(pvt, AST_CONTROL_CONGESTION);
			break;
		case AT_DDSETEX:
			ast_debug(1, "[%s] AT^DDSETEX failed\n", pvt->id);
			break;
		case AT_CHUP:
			ast_debug(1, "[%s] error sending hangup, disconnecting\n", pvt->id);
			goto e_return;
		case AT_CMGR:
			ast_debug(1, "[%s] error reading sms message\n", pvt->id);
			pvt->incoming_sms = 0;
			break;
		case AT_CMGS:
			ast_debug(1, "[%s] error sending sms message\n", pvt->id);
			pvt->outgoing_sms = 0;
			break;
		case AT_VTS:
			ast_debug(1, "[%s] error sending digit\n", pvt->id);
			break;
		case AT_UNKNOWN:
		default:
			ast_debug(1, "[%s] recieved ERROR for unhandled request: %s\n", pvt->id, at_msg2str(entry->response_to));
			break;
		}
		msg_queue_free_and_pop(pvt);
	} else if (entry) {
		ast_debug(1, "[%s] recieved AT message 'ERROR' when expecting %s, ignoring\n", pvt->id, at_msg2str(entry->expected));
	} else {
		ast_debug(1, "[%s] recieved unexpected AT message 'ERROR'\n", pvt->id);
	}

	return 0;

e_return:
	msg_queue_free_and_pop(pvt);
	return -1;
}

/*!
 * \brief Handle ^CONF AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_conf(struct dc_pvt *pvt, char *buf)
{
	return 0;
}

/*!
 * \brief Handle ^ORIG AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_orig(struct dc_pvt *pvt, char *buf)
{
	return 0;
}

/*!
 * \brief Handle +CSSI AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cssi(struct dc_pvt *pvt, char *buf)
{
	if (pvt->outgoing) {
		ast_debug(1, "[%s] remote alerting\n", pvt->id);
		dc_queue_control(pvt, AST_CONTROL_RINGING);
	}
	return 0;
}

/*!
 * \brief Handle +CSSU AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cssu(struct dc_pvt *pvt, char *buf)
{
        return 0;
}

/*!
 * \brief Handle ^CEND AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cend(struct dc_pvt *pvt, char *buf)
{
	ast_debug(1, "[%s] line disconnected\n", pvt->id);
	if (pvt->owner) {
		ast_debug(1, "[%s] hanging up owner\n", pvt->id);
		if (dc_queue_hangup(pvt)) {
			ast_log(LOG_ERROR, "[%s] error queueing hangup, disconnectiong...\n", pvt->id);
			return -1;
		}
	}
	pvt->needchup = 0;
	pvt->incoming = 0;
	pvt->outgoing = 0;

	return 0;
}

/*!
 * \brief Handle ^CONN AT messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_conn(struct dc_pvt *pvt, char *buf)
{
	if (pvt->outgoing) {
		ast_debug(1, "[%s] remote end answered\n", pvt->id);
		dc_queue_control(pvt, AST_CONTROL_ANSWER);
	} else if (pvt->incoming && pvt->answered) {
		ast_setstate(pvt->owner, AST_STATE_UP);
	}

	return 0;
}

/*!
 * \brief Handle AT+CLIP messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_clip(struct dc_pvt *pvt, char *buf)
{
	char *clip;
	struct ast_channel *chan;

	ast_debug(1, "[%s] executing handle_response_clip\n", pvt->id);

	if (!(clip = dc_parse_clip(pvt, buf))) {
		ast_debug(1, "[%s] error parsing CLIP: %s\n", pvt->id, buf);
	}
	
	if (pvt->needring == 0)
	{
		pvt->incoming = 1;
		
		if (!(chan = dc_new(AST_STATE_RING, pvt, clip))) {
			ast_log(LOG_ERROR, "[%s] unable to allocate channel for incoming call\n", pvt->id);
			dc_send_chup(pvt);
			msg_queue_push(pvt, AT_OK, AT_CHUP);
			return -1;
		}

		/* from this point on, we need to send a chup in the event of a
		 * hangup */
		pvt->needchup = 1;
		/* We dont need to send ring a 2nd time */
		pvt->needring = 1;

		if (ast_pbx_start(chan)) {
			ast_log(LOG_ERROR, "[%s] unable to start pbx on incoming call\n", pvt->id);
			dc_ast_hangup(pvt);
			return -1;
		}
	}

	return 0;
}

/*!
 * \brief Handle RING messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_ring(struct dc_pvt *pvt, char *buf)
{
	pvt->incoming = 1;
	return 0;
}

/*!
 * \brief Handle AT+CMTI messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cmti(struct dc_pvt *pvt, char *buf)
{
	int index = dc_parse_cmti(pvt, buf);
	if (index > 0) {
		ast_debug(1, "[%s] incoming sms message\n", pvt->id);

		if (dc_send_cmgr(pvt, index)
				|| msg_queue_push(pvt, AT_CMGR, AT_CMGR)) {
			ast_debug(1, "[%s] error sending CMGR to retrieve SMS message\n", pvt->id);
			return -1;
		}

		pvt->incoming_sms = 1;
		return 0;
	} else {
		ast_debug(1, "[%s] error parsing incoming sms message alert, disconnecting\n", pvt->id);
		return -1;
	}
}

/*!
 * \brief Handle AT+CMGR messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cmgr(struct dc_pvt *pvt, char *buf)
{
	char *from_number, *text;
	struct ast_channel *chan;
	struct msg_queue_entry *msg;

	if ((msg = msg_queue_head(pvt)) && msg->expected == AT_CMGR) {
		msg_queue_free_and_pop(pvt);

		if (dc_parse_cmgr(pvt, buf, &from_number, &text)
				|| msg_queue_push(pvt, AT_OK, AT_CMGR)) {

			ast_debug(1, "[%s] error parsing sms message, disconnecting\n", pvt->id);
			return -1;
		}

		/* XXX this channel probably does not need to be associated with this pvt */
		if (!(chan = dc_new(AST_STATE_DOWN, pvt, NULL))) {
			ast_debug(1, "[%s] error creating sms message channel, disconnecting\n", pvt->id);
			return -1;
		}

		strcpy(chan->exten, "sms");
		pbx_builtin_setvar_helper(chan, "SMSSRC", from_number);
		pbx_builtin_setvar_helper(chan, "SMSTXT", text);

		if (ast_pbx_start(chan)) {
			ast_log(LOG_ERROR, "[%s] unable to start pbx on incoming sms\n", pvt->id);
			dc_ast_hangup(pvt);
		}
	} else {
		ast_debug(1, "[%s] got unexpected +CMGR message, ignoring\n", pvt->id);
	}

	return 0;
}

/*!
 * \brief Send an SMS message from the queue.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_sms_prompt(struct dc_pvt *pvt, char *buf)
{
	struct msg_queue_entry *msg;
	if (!(msg = msg_queue_head(pvt))) {
		ast_debug(1, "[%s] error, got sms prompt with no pending sms messages\n", pvt->id);
		return 0;
	}

	if (msg->expected != AT_SMS_PROMPT) {
		ast_debug(1, "[%s] error, got sms prompt but no pending sms messages\n", pvt->id);
		return 0;
	}

	if (dc_send_sms_text(pvt, msg->data)
			|| msg_queue_push(pvt, AT_OK, AT_CMGS)) {
		msg_queue_free_and_pop(pvt);
		ast_debug(1, "[%s] error sending sms message\n", pvt->id);
		return 0;
	}

	msg_queue_free_and_pop(pvt);
	return 0;
}

/*!
 * \brief Handle CUSD messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cusd(struct dc_pvt *pvt, char *buf)
{
	char *cusd;
	struct ast_channel *chan;
 
	if (!(cusd = dc_parse_cusd(pvt, buf))) {
		ast_verb(1, "[%s] error parsing CUSD: %s\n", pvt->id, buf);
		return 0;
	}

	ast_verb(1, "Got CUSD response from device %s: %s\n", pvt->id,cusd);
	
	/* XXX this channel probably does not need to be associated with this pvt */
	if (!(chan = dc_new(AST_STATE_DOWN, pvt, NULL))) {
		ast_debug(1, "[%s] error creating cusd message channel, disconnecting\n", pvt->id);
		return -1;
	}

	strcpy(chan->exten, "cusd");
	pbx_builtin_setvar_helper(chan, "CUSDTXT", cusd);

	if (ast_pbx_start(chan)) {
		ast_log(LOG_ERROR, "[%s] unable to start pbx on incoming cusd\n", pvt->id);
		dc_ast_hangup(pvt);
	}

	return 0;
}

/*!
 * \brief Handle BUSY messages.
 * \param pvt a dc_pvt structure
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_busy(struct dc_pvt *pvt)
{
	pvt->hangupcause = AST_CAUSE_USER_BUSY;
	pvt->needchup = 1;
	dc_queue_control(pvt, AST_CONTROL_BUSY);
	return 0;
}
 
/*!
 * \brief Handle NO DIALTONE messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_no_dialtone(struct dc_pvt *pvt, char *buf)
{
	ast_verb(1, "[%s] datacard reports NO DIALTONE\n", pvt->id);
	pvt->needchup = 1;
	dc_queue_control(pvt, AST_CONTROL_CONGESTION);
	return 0;
}

/*!
 * \brief Handle NO CARRIER messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_no_carrier(struct dc_pvt *pvt, char *buf)
{
	ast_verb(1, "[%s] datacard reports NO CARRIER\n", pvt->id);
	pvt->needchup = 1;
	dc_queue_control(pvt, AST_CONTROL_CONGESTION);
	return 0;
}

/*!
 * \brief Handle +CPIN messages.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_cpin(struct dc_pvt *pvt, char *buf)
{
	return dc_parse_cpin(pvt,buf);
}

/*!
 * \brief Handle ^RSSI messages. Here we get the signal strength.
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_rssi(struct dc_pvt *pvt, char *buf)
{
	pvt->rssi = dc_parse_rssi(pvt, buf);

	if (pvt->rssi == -1) return -1;

	return 0;
}

/*!
 * \brief Handle ^MODE messages. Here we get the link mode (GSM, UMTS, EDGE...).
 * \param pvt a dc_pvt structure
 * \param buf a null terminated buffer containing an AT message
 * \retval 0 success
 * \retval -1 error
 */
static int handle_response_mode(struct dc_pvt *pvt, char *buf)
{
	pvt->linkmode = dc_parse_linkmode(pvt, buf);
	pvt->linksubmode = dc_parse_linksubmode(pvt, buf);

	if (pvt->linkmode == -1 || pvt->linksubmode == -1) return -1;

	return 0;
}

static void *do_monitor_phone(void *data)
{
	struct dc_pvt *pvt = (struct dc_pvt *)data;
	char buf[256];
	int t;
	at_message_t at_msg;
	struct msg_queue_entry *entry;

	/* Note: At one point the initilization procedure was neatly contained
	 * in the dc_init() function, but that initilization method did not
	 * work with non standard devices.  As a result, the initilization
	 * procedure is not spread throughout the event handling loop.
	 */

	/* start initilization with the ATE0 request (disable echo) */
	ast_mutex_lock(&pvt->lock);
	pvt->timeout = 10000;
	if (dc_send_ate0(pvt) || msg_queue_push(pvt, AT_OK, AT_E0)) {
		ast_debug(1, "[%s] error sending ATE0\n", pvt->id);
		goto e_cleanup;
	}
	ast_mutex_unlock(&pvt->lock);

	while (!check_unloading()) {
		ast_mutex_lock(&pvt->lock);
		t = pvt->timeout;
		ast_mutex_unlock(&pvt->lock);

		if (pvt->data_socket == -1) {
			ast_log(LOG_ERROR, "Lost data connection to Datacard %s.\n", pvt->id);
			goto e_cleanup;
		}

		if (pvt->audio_socket == -1) {
			ast_log(LOG_ERROR, "Lost audio connection to Datacard %s.\n", pvt->id);
			goto e_cleanup;
		}

		if (!rfcomm_wait(pvt->data_socket, &t)) {
			ast_debug(1, "[%s] timeout waiting for rfcomm data, disconnecting\n", pvt->id);
			ast_mutex_lock(&pvt->lock);
			if (!pvt->initialized) {
				if ((entry = msg_queue_head(pvt))) {
					switch (entry->response_to) {
					default:
						ast_debug(1, "[%s] timeout while waiting for %s in response to %s\n", pvt->id, at_msg2str(entry->expected), at_msg2str(entry->response_to));
						break;
					}
				}
			}
			ast_mutex_unlock(&pvt->lock);
			goto e_cleanup;
		}

		if ((at_msg = at_read_full(pvt->data_socket, buf, sizeof(buf))) < 0) {
			/* XXX gnu specific strerror_r is assummed here, this
			 * is not really safe.  See the strerror(3) man page
			 * for more info. */
			ast_debug(1, "[%s] error reading from device: %s (%d)\n", pvt->id, strerror_r(errno, buf, sizeof(buf)), errno);
			break;
		}

		ast_debug(1, "[%s] %s\n", pvt->id, buf);

		switch (at_msg) {
		case AT_OK:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_ok(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CMS_ERROR:
		case AT_ERROR:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_error(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_RING:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_ring(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CSSN:
			break;
		case AT_CSSI:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cssi(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CSSU:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cssu(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CONN:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_conn(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CEND:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cend(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CONF:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_conf(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_ORIG:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_orig(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_RSSI:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_rssi(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_BOOT:
			break;
		case AT_CLIP:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_clip(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CMTI:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cmti(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CMGR:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cmgr(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_SMS_PROMPT:
			ast_mutex_lock(&pvt->lock);
			if (handle_sms_prompt(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CUSD:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cusd(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_BUSY:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_busy(pvt)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_NO_DIALTONE:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_no_dialtone(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_NO_CARRIER:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_no_carrier(pvt, buf)) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_CPIN:
			ast_mutex_lock(&pvt->lock);
			if (handle_response_cpin(pvt, buf) != 0) {
				ast_mutex_unlock(&pvt->lock);
				goto e_cleanup;
			}
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_MODE:
			// An error here is not fatal. Just keep going.
			ast_mutex_lock(&pvt->lock);
			handle_response_mode(pvt, buf);
			ast_mutex_unlock(&pvt->lock);
			break;
		case AT_UNKNOWN:
			ast_debug(1, "[%s] ignoring unknown message: %s\n", pvt->id, buf);
			break;
		case AT_PARSE_ERROR:
			ast_debug(1, "[%s] error parsing message\n", pvt->id);
			goto e_cleanup;
		case AT_READ_ERROR:
			ast_debug(1, "[%s] error reading from device: %s (%d)\n", pvt->id, strerror_r(errno, buf, sizeof(buf)), errno);
			goto e_cleanup;
		}
	}

e_cleanup:

	if (!pvt->initialized)
		ast_verb(3, "Error initializing Datacard %s.\n", pvt->id);

	disconnect_datacard(pvt);

	return NULL;
}

static int disconnect_datacard(struct dc_pvt *pvt)
{
	ast_mutex_lock(&pvt->lock);
	if (pvt->owner) {
		ast_debug(1, "[%s] Datacard disconnected, hanging up owner\n", pvt->id);
		pvt->needchup = 0;
		dc_queue_hangup(pvt);
	}

	close(pvt->data_socket);
	close(pvt->audio_socket);
	pvt->data_socket = -1;
	pvt->audio_socket = -1;

	msg_queue_flush(pvt);

	pvt->connected = 0;
	pvt->initialized = 0;

	ast_mutex_unlock(&pvt->lock);

	ast_verb(3, "Datacard %s has disconnected.\n", pvt->id);
	manager_event(EVENT_FLAG_SYSTEM, "DatacardStatus", "Status: Disconnect\r\nDevice: %s\r\n", pvt->id);	

	return 1;
}

static int start_monitor(struct dc_pvt *pvt)
{

	pvt->data_socket = pvt->data_socket;

	if (ast_pthread_create_background(&pvt->monitor_thread, NULL, do_monitor_phone, pvt) < 0) {
		pvt->monitor_thread = AST_PTHREADT_NULL;
		return 0;
	}

	return 1;

}

static void *do_discovery(void *data)
{
	struct dc_pvt *pvt;

	while (!check_unloading()) {
		AST_RWLIST_RDLOCK(&devices);
		AST_RWLIST_TRAVERSE(&devices, pvt, entry) {
			ast_mutex_lock(&pvt->lock);
			if (!pvt->connected) {
				ast_verb(3, "Datacard %s trying to connect on %s...\n", pvt->id, pvt->data_tty_str);
				if ((pvt->data_socket = dc_data_connect(pvt->data_tty_str)) > -1) {
					if ((pvt->audio_socket = dc_audio_connect(pvt->audio_tty_str)) > -1) {
						if (start_monitor(pvt)) {
							pvt->connected = 1;
							manager_event(EVENT_FLAG_SYSTEM, "DatacardStatus", "Status: Connect\r\nDevice: %s\r\n", pvt->id);
							ast_verb(3, "Datacard %s has connected, initializing...\n", pvt->id);
						}
					}
				}
			}
			ast_mutex_unlock(&pvt->lock);
		}
		AST_RWLIST_UNLOCK(&devices);

		/* Go to sleep (only if we are not unloading) */

		if (!check_unloading())
			sleep(discovery_interval);
	}

	return NULL;
}

/*

	Module

*/

/*!
 * \brief Load a device from the configuration file.
 * \param cfg the config to load the device from
 * \param cat the device to load
 * \return NULL on error, a pointer to the device that was loaded on success
 */
static struct dc_pvt *dc_load_device(struct ast_config *cfg, const char *cat)
{
	struct dc_pvt *pvt;
	struct ast_variable *v;
	const char *audio_tty_str, *data_tty_str;
	ast_debug(1, "Reading configuration for device %s.\n", cat);

	audio_tty_str = ast_variable_retrieve(cfg, cat, "audio");
	data_tty_str = ast_variable_retrieve(cfg, cat, "data");
	if (ast_strlen_zero(audio_tty_str) || ast_strlen_zero(data_tty_str)) {
		ast_log(LOG_ERROR, "Skipping device %s. Missing required audio_tty or data_tty setting.\n", cat);
		goto e_return;
	}

	/* create and initialize our pvt structure */
	if (!(pvt = ast_calloc(1, sizeof(*pvt)))) {
		ast_log(LOG_ERROR, "Skipping device %s. Error allocating memory.\n", cat);
		goto e_return;
	}

	ast_mutex_init(&pvt->lock);
	AST_LIST_HEAD_INIT_NOLOCK(&pvt->msg_queue);

	/* set some defaults */

	ast_copy_string(pvt->context, "default", sizeof(pvt->context));

	/* populate the pvt structure */

	ast_copy_string(pvt->id, cat, sizeof(pvt->id));
	ast_copy_string(pvt->data_tty_str, data_tty_str, sizeof(pvt->data_tty_str));
	ast_copy_string(pvt->audio_tty_str, audio_tty_str, sizeof(pvt->audio_tty_str));
	pvt->timeout = -1;
	pvt->data_socket = -1;
	pvt->audio_socket = -1;
	pvt->monitor_thread = AST_PTHREADT_NULL;
	pvt->needring = 0;
	pvt->incoming = 0;
	pvt->has_sms = 0;
	pvt->has_voice = 0;
	pvt->rssi = 0;
	pvt->linkmode = 0;
	pvt->linksubmode = 0;
	pvt->volume_synchronized = 0;
	pvt->volume_adjustment = 0;

	/* setup the smoother */
	if (!(pvt->smoother = ast_smoother_new(DEVICE_FRAME_SIZE))) {
		ast_log(LOG_ERROR, "Skipping device %s. Error setting up frame smoother.\n", cat);
		goto e_free_pvt;
	}

	/* setup the dsp */
	if (!(pvt->dsp = ast_dsp_new())) {
		ast_log(LOG_ERROR, "Skipping device %s. Error setting up dsp for dtmf detection.\n", cat);
		goto e_free_smoother;
	}

	ast_dsp_set_features(pvt->dsp, DSP_FEATURE_DIGIT_DETECT);
	ast_dsp_set_digitmode(pvt->dsp, DSP_DIGITMODE_DTMF | DSP_DIGITMODE_RELAXDTMF);

	for (v = ast_variable_browse(cfg, cat); v; v = v->next) {
		if (!strcasecmp(v->name, "context")) {
			ast_copy_string(pvt->context, v->value, sizeof(pvt->context));
		} else if (!strcasecmp(v->name, "group")) {
			/* group is set to 0 if invalid */
			pvt->group = atoi(v->value);
		} else if (!strcasecmp(v->name, "rxgain")) {
			/* volume_adjustment is set to 0 if invalid */
			pvt->volume_adjustment = atoi(v->value);
		}
	}

	AST_RWLIST_WRLOCK(&devices);
	AST_RWLIST_INSERT_HEAD(&devices, pvt, entry);
	AST_RWLIST_UNLOCK(&devices);
	ast_debug(1, "Loaded device %s.\n", pvt->id);
	ast_log(LOG_NOTICE, "Loaded device %s. data_tty: %s \n", pvt->id, pvt->data_tty_str);
	ast_log(LOG_NOTICE, "Loaded device %s. audio_tty: %s \n", pvt->id, pvt->audio_tty_str);

	return pvt;

e_free_smoother:
	ast_smoother_free(pvt->smoother);
e_free_pvt:
	ast_free(pvt);
e_return:
	return NULL;
}

static int dc_load_config(void)
{
	struct ast_config *cfg;
	const char *cat;
	struct ast_variable *v;
	struct ast_flags config_flags = { 0 };

	cfg = ast_config_load(DC_CONFIG, config_flags);
	if (!cfg)
		return -1;

	/* parse [general] section */
	for (v = ast_variable_browse(cfg, "general"); v; v = v->next) {
		if (!strcasecmp(v->name, "interval")) {
			if (!sscanf(v->value, "%d", &discovery_interval)) {
				ast_log(LOG_NOTICE, "error parsing 'interval' in general section, using default value\n");
			}
		}
	}

	/* now load devices */
	for (cat = ast_category_browse(cfg, NULL); cat; cat = ast_category_browse(cfg, cat)) {
		if (strcasecmp(cat, "general")) {
			dc_load_device(cfg, cat);
		}
	}

	ast_config_destroy(cfg);

	return 0;
}

/*!
 * \brief Check if the module is unloading.
 * \retval 0 not unloading
 * \retval 1 unloading
 */
static inline int check_unloading()
{
	int res;
	ast_mutex_lock(&unload_mutex);
	res = unloading_flag;
	ast_mutex_unlock(&unload_mutex);

	return res;
}

/*!
 * \brief Set the unloading flag.
 */
static inline void set_unloading()
{
	ast_mutex_lock(&unload_mutex);
	unloading_flag = 1;
	ast_mutex_unlock(&unload_mutex);
}

static int unload_module(void)
{
	struct dc_pvt *pvt;

	/* First, take us out of the channel loop */
	ast_channel_unregister(&dc_tech);

	/* Unregister the CLI & APP */
	ast_cli_unregister_multiple(dc_cli, sizeof(dc_cli) / sizeof(dc_cli[0]));
	ast_unregister_application(app_dcstatus);
	ast_unregister_application(app_dcsendsms);

	/* signal everyone we are unloading */
	set_unloading();

	/* Kill the discovery thread */
	if (discovery_thread != AST_PTHREADT_NULL) {
		pthread_kill(discovery_thread, SIGURG);
		pthread_join(discovery_thread, NULL);
	}

	/* Destroy the device list */
	AST_RWLIST_WRLOCK(&devices);
	while ((pvt = AST_RWLIST_REMOVE_HEAD(&devices, entry))) {
		if (pvt->monitor_thread != AST_PTHREADT_NULL) {
			pthread_kill(pvt->monitor_thread, SIGURG);
			pthread_join(pvt->monitor_thread, NULL);
		}

		close(pvt->audio_socket);
		close(pvt->data_socket);

		msg_queue_flush(pvt);

		ast_smoother_free(pvt->smoother);
		ast_dsp_free(pvt->dsp);
		ast_free(pvt);
	}
	AST_RWLIST_UNLOCK(&devices);

	return 0;
}

static int load_module(void)
{
	if (dc_load_config()) {
		ast_log(LOG_ERROR, "Errors reading config file %s. Not loading module.\n", DC_CONFIG);
		return AST_MODULE_LOAD_DECLINE;
	}

	/* Spin the discovery thread */
	if (ast_pthread_create_background(&discovery_thread, NULL, do_discovery, NULL) < 0) {
		ast_log(LOG_ERROR, "Unable to create discovery thread.\n");
		goto e_cleanup;
	}

	/* register our channel type */
	if (ast_channel_register(&dc_tech)) {
		ast_log(LOG_ERROR, "Unable to register channel class %s\n", "Datacard");
		goto e_cleanup;
	}

	ast_cli_register_multiple(dc_cli, sizeof(dc_cli) / sizeof(dc_cli[0]));
	ast_register_application(app_dcstatus, dc_status_exec, dcstatus_synopsis, dcstatus_desc);
	ast_register_application(app_dcsendsms, dc_sendsms_exec, dcsendsms_synopsis, dcsendsms_desc);

	return AST_MODULE_LOAD_SUCCESS;

e_cleanup:

	return AST_MODULE_LOAD_FAILURE;
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_DEFAULT, "Datacard Channel Driver",
		.load = load_module,
		.unload = unload_module,
);
