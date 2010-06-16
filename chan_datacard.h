/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

#define CONFIG_FILE		"datacard.conf"

#define DEVICE_FRAME_SIZE	320
#define CHANNEL_FRAME_SIZE	320
#define DEVICE_FRAME_FORMAT	AST_FORMAT_SLINEAR

struct msg_queue_entry;
typedef struct dc_pvt
{
	struct ast_channel *owner;			/* Channel we belong to, possibly NULL */
	struct ast_frame fr;				/* "null" frame */
	ast_mutex_t lock;				/*!< pvt lock */
	/*! queue for messages we are expecting */
	AST_LIST_HEAD_NOLOCK(msg_queue, msg_queue_entry) msg_queue;
	char id[31];					/* The id from datacard.conf */
	int group;					/* group number for group dialling */
	char context[AST_MAX_CONTEXT];			/* the context for incoming calls */
	struct dc_pvt *pvt;				/*!< pvt pvt */
	char io_buf[CHANNEL_FRAME_SIZE + AST_FRIENDLY_OFFSET];
	struct ast_smoother *smoother;			/* our smoother, for making 320 byte frames */
	char audio_tty_str[256];
	char data_tty_str[256];
	int audio_socket;				/* audio socket descriptor */
	int data_socket;				/* rfcomm socket descriptor */
	pthread_t monitor_thread;			/* monitor thread handle */
	int timeout;					/*!< used to set the timeout for rfcomm data (may be used in the future) */
	unsigned int has_sms:1;
	unsigned int has_voice:1;
	struct ast_dsp *dsp;
	int hangupcause;
	int initialized:1;		/*!< whether a service level connection exists or not */
	int rssi;
	int ber;
	int linkmode;
	int linksubmode;
	int rxgain;
	int txgain;
	char provider_name[32];
	char manufacturer[32];
	char model[32];
	char firmware[32];
	char imei[17];
	int sms_storage_position;
	unsigned int auto_delete_sms:1;
	unsigned int use_ucs2_encoding:1;
	unsigned int reset_datacard:1;
	int u2diag;
	char number[1024];

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
}
pvt_t;


/* CLI */

static char*			cli_show_devices	(struct ast_cli_entry*, int, struct ast_cli_args*);
static char*			cli_show_device		(struct ast_cli_entry*, int, struct ast_cli_args*);
static char*			cli_cmd			(struct ast_cli_entry*, int, struct ast_cli_args*);
static char*			cli_cusd		(struct ast_cli_entry*, int, struct ast_cli_args*);

static struct ast_cli_entry cli[] = {
	AST_CLI_DEFINE (cli_show_devices,	"Show Datacard devices state"),
	AST_CLI_DEFINE (cli_show_device,	"Show Datacard device state and config"),
	AST_CLI_DEFINE (cli_cmd,		"Send commands to port for debugging"),
	AST_CLI_DEFINE (cli_cusd,		"Send CUSD commands to the datacard"),
};


/* Manager */

#ifdef __MANAGER__

static int			manager_show_devices	(struct mansession*, const struct message*);
static int			manager_send_cusd	(struct mansession*, const struct message*);
static int			manager_send_sms	(struct mansession*, const struct message*);
static char*			manager_event_new_cusd	(pvt_t*, char*);
static char*			manager_event_new_sms	(pvt_t*, char*, char*);

static char* manager_show_devices_desc =
	"Description: Lists Datacard devices in text format with details on current status.\n\n"
	"DatacardShowDevicesComplete.\n"
	"Variables:\n"
	"	ActionID: <id>		Action ID for this transaction. Will be returned.\n";

static char* manager_send_cusd_desc =
	"Description: Send a cusd message to a datacard.\n\n"
	"Variables: (Names marked with * are required)\n"
	"	ActionID: <id>		Action ID for this transaction. Will be returned.\n"
	"	*Device:  <device>	The datacard to which the cusd code will be send.\n"
	"	*CUSD:    <code>	The cusd code that will be send to the device.\n";

static char* manager_send_sms_desc =
	"Description: Send a sms message from a datacard.\n\n"
	"Variables: (Names marked with * are required)\n"
	"	ActionID: <id>		Action ID for this transaction. Will be returned.\n"
	"	*Device:  <device>	The datacard to which the cusd code will be send.\n"
	"	*Number:  <number>	The phone number to which the sms will be send.\n"
	"	*Message: <message>	The sms message that will be send.\n";

#endif /* __MANAGER__ */


/* Dialplan app */

#ifdef __APP__

static char* app_status			= "DatacardStatus";
static char* app_status_synopsis	= "DatacardStatus(Device,Variable)";
static char* app_status_desc		=
	"DatacardStatus(Device,Variable)\n"
	"  Device - Id of device from datacard.conf\n"
	"  Variable - Variable to store status in will be 1-3.\n"
	"             In order, Disconnected, Connected & Free, Connected & Busy.\n";

static char* app_send_sms		= "DatacardSendSMS";
static char* app_send_sms_synopsis	= "DatacardSendSMS(Device,Dest,Message)";
static char* app_send_sms_desc		=
	"DatacardSendSms(Device,Dest,Message)\n"
	"  Device - Id of device from datacard.conf\n"
	"  Dest - destination\n"
	"  Message - text of the message\n";

#endif /* __APP__ */
