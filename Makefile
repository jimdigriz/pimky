CFLAGS  = -pipe -Wall -pedantic -D_POSIX_C_SOURCE=200112L
LDFLAGS = -lrt

KERNEL  = $(shell uname -s)

OBJS    = utils.o net.o pim.o mld.o pimky.o

all: env pimky

env:
ifeq ($(KERNEL), Linux)
CFLAGS += -D_BSD_SOURCE
#else ifeq ($(KERNEL), FreeBSD)
#CFLAGS += -D__BSD_VISIBLE
else ifeq ($(KERNEL), Darwin)
CFLAGS += -D_DARWIN_C_SOURCE
else
	@echo Sorry \'$(KERNEL)\' is not supported
	@false
endif
ifdef DEBUG
	CFLAGS  += -g -pg -O0
	LDFLAGS += -g -pg
else
	CFLAGS  += -DNDEBUG -Os
endif

pimky: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o pimky
ifndef DEBUG
	$(CROSS_COMPILE)strip pimky
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJS) pimky
