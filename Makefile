CFLAGS=-pipe -Wall -pedantic -D_POSIX_C_SOURCE=200112L
LDFLAGS=-lrt

ifdef DEBUG
	CFLAGS += -g -O0 -pg
	LDFLAGS += -g -pg
else
	CFLAGS += -DNDEBUG -Os
endif

OBJS = utils.o net.o pim.o mld.o pimky.o

all: oscheck pimky

pimky: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o pimky
ifndef DEBUG
	$(CROSS_COMPILE)strip pimky
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJS) pimky

KERNEL=$(shell uname -s)

oscheck:
ifeq ($(KERNEL), Linux)
CFLAGS += -D_BSD_SOURCE
else ifeq ($(KERNEL), FreeBSD)
CFLAGS += -D__BSD_VISIBLE
else ifeq ($(KERNEL), Darwin)
CFLAGS += -D__BSD_VISIBLE
else
	@echo Sorry \'$(KERNEL)\' is not supported
	@false
endif
