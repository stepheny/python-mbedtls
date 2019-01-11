#include "mbedtls/platform_util.h"

#include <stdio.h>
#include <stdlib.h>

void mbedtls_param_failed( const char *failure_condition,
                          const char *file,
                          int line )
{
   printf( "%s:%i: Input param failed - %s\n",
           file, line, failure_condition );
   exit( EXIT_FAILURE );
}
