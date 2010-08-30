--------------------------------------------------
chan_datacard channel driver for Huawei UMTS cards
--------------------------------------------------

WARNING:

This channel driver is in beta stage.
I am not responsible if this channel driver will eat your money on
your SIM card or do any unpredicted things.

Please use a recent Linux kernel, 2.6.33+ recommended.
If you use FreeBSD, 8.0+ recommended.

This channel driver should work with the folowing UMTS cards:
* Huawei K3715
* Huawei E169 / K3520
* Huawei E1550

This channel is known NOT to work with the folowing UMTS cards:
* Huawei E160 / K3565

Before using the channel driver make sure to:
* Disable call waiting on your SIM card
* Disable PIN code on your SIM card

Supported features:
* Place voice calls and terminate voice calls
* Send SMS and receive SMS
* Send and receive USSD commands / messages

Some useful AT commands:
AT+CCWA=0,0,1
AT+CFUN=1,1
AT^CARDLOCK="<code>"
AT^SYSCFG=13,0,3FFFFFFF,0,3
AT^U2DIAG=0

Here is an example for the dialplan:

[datacard-incoming]
exten => sms,1,Verbose(Incoming SMS from ${CALLERID(num)} ${SMS})
exten => sms,n,System(echo '${STRFTIME(${EPOCH},,%Y-%m-%d %H:%M:%S)} - ${DATACARD} - ${CALLERID(num)}: ${SMS}' >> /var/log/asterisk/sms.txt)
exten => sms,n,Hangup()

exten => ussd,1,Verbose(Incoming USSD: ${USSD})
exten => ussd,n,System(echo '${STRFTIME(${EPOCH},,%Y-%m-%d %H:%M:%S)} - ${DATACARD}: ${USSD}' >> /var/log/asterisk/ussd.txt)
exten => ussd,n,Hangup()

exten => s,1,Dial(SIP/2001@othersipserver)
exten => s,n,Hangup()

[othersipserver-incoming]

exten => _X.,1,Dial(Datacard/r1/${EXTEN})
exten => _X.,n,Hangup

you can also use this:

Call using a specific group:
exten => _X.,1,Dial(Datacard/g1/${EXTEN})

Call using a specific datacard:
exten => _X.,1,Dial(Datacard/datacard0/${EXTEN})

Call using a specific provider name:
exten => _X.,1,Dial(Datacard/p:PROVIDER NAME/${EXTEN})

Call using a specific IMEI:
exten => _X.,1,Dial(Datacard/i:123456789012345/${EXTEN})

Call using a IMSI prefix:
exten => _X.,1,Dial(Datacard/s:25099/${EXTEN})

How to store your own number:

datacard cmd datacard0 AT+CPBS=\"ON\"
datacard cmd datacard0 AT+CPBW=1,\"+123456789\",145

