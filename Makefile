CFLAGS=-pipe -Wall -pedantic -D_POSIX_C_SOURCE=200112L -D_BSD_SOURCE
LDFLAGS=-lrt

ifdef DEBUG
	CFLAGS += -g -O0 -pg
	LDFLAGS += -g -pg
else
	CFLAGS += -DNDEBUG -Os
endif

OBJS = utils.o net.o pim.o mld.o pimky.o

pimky: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o pimky
ifndef DEBUG
	$(CROSS_COMPILE)strip pimky
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJS) pimky
