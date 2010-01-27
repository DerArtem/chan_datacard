OPTFLAGS=-O2

CFLAGS=-Wall -g $(OPTFLAGS) -fPIC -D_GNU_SOURCE

TARGETS = chan_datacard.so

SOURCES = Makefile chan_datacard.c char_conv.c char_conv.h

DESTDIR = 

all: $(TARGETS)

chan_datacard.so: char_conv.o

%.so: %.c
	$(CC) $(CFLAGS) -DAST_MODULE=\"$*\" -shared -o $@ $^ $(LIBS)

install: $(TARGETS)
	install -m644 $(TARGETS) $(DESTDIR)/usr/lib/asterisk/modules

clean:
	rm -rf *.o *.so
