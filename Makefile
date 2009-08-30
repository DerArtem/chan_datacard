OPTFLAGS=-O2

CFLAGS=-Wall -g $(OPTFLAGS) -fPIC -D_GNU_SOURCE

TARGETS = chan_datacard.so

SOURCES = Makefile chan_datacard.c

DESTDIR = 

all: $(TARGETS)

chan_datacard.so:

%.so: %.c
	$(CC) $(CFLAGS) -DAST_MODULE=\"$*\" -shared -o $@ $^ $(LIBS)

install: $(TARGETS)
	install -m644 $(TARGETS) $(DESTDIR)/usr/lib/asterisk/modules

clean:
	rm -rf *.so
