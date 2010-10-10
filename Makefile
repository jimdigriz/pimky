CFLAGS  = -pipe -Wall -pedantic -D_POSIX_C_SOURCE=200112L
LDFLAGS = -lrt

KERNEL  = $(shell uname -s)

OBJS    = utils.o net.o route.o pim.o mld.o pimky.o

all: env pimky

env:
ifeq ($(KERNEL), Linux)
CFLAGS += -D_BSD_SOURCE
else ifeq ($(KERNEL), FreeBSD)
	@echo FreeBSD untested, expect your pants to explode!
CFLAGS += -D__BSD_VISIBLE
else
	@echo Sorry \'$(KERNEL)\' is not supported
	@false
endif

ifdef EMBEDDED
	CFLAGS  += -DNDEBUG -Os
else 
	CFLAGS  += -g -O0
	LDFLAGS += -g

	ifdef PROFILE
		CFLAGS  += -pg
		LDFLAGS += -pg
	endif
endif

pimky: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o pimky
ifdef EMBEDDED
	$(CROSS_COMPILE)strip pimky
endif

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJS) pimky
