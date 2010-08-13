#include <stdio.h>
#include <time.h>

#include "pimky.h"

void mld_query_send() {
	fprintf(stderr, "%d, sent igmp/mld query\n", (int) time(NULL));
}
