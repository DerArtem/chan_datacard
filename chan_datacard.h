/*
   Copyright (C) 2009 - 2010 Artem Makhutov
   Artem Makhutov <artem@makhutov.org>
   http://www.makhutov.org
*/

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
	char subscriber_number[1024];

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
