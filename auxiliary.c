#include <stdio.h>
#include "auxiliary.h"

extern int print_usage(void)
{
  printf("Usage: pscan <host> [lower_limit] [upper_limit]\n");
  printf("<host>: Set the target, its mandatory!\n");
  printf("[lower_limit]: Optional to set the start port of the scan range\n");
  printf("[upper_limit]: Optional to set the end port of the scan range\n\n");
  printf("pscan will automatically scan the first 1024 ports if not told otherwise.\n");

  return 0;
}