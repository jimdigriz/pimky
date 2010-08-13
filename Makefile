#CFLAGS=-pipe -Wall -std=c99 -pedantic -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=600 -O2
CFLAGS=-pipe -Wall -std=c99 -pedantic -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=600 -O0 -g
LDFLAGS=-lrt

STRIP=strip

OBJS = utils.o pim.o mld.o pimky.o

pimky: $(OBJS)
	$(CROSS_COMPILE)$(CC) $(LDFLAGS) $^ -o pimky
	#$(CROSS_COMPILE)$(STRIP) pimky

%.o: %.c
	$(CROSS_COMPILE)$(CC) -c $(CFLAGS) $<

clean:
	rm -f $(OBJS) pimky
