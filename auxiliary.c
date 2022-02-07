#include <stdio.h>
#include "auxiliary.h"

extern int check_usage(int *argument)
{
  if (*argument == 2)
  {
    return 0;
  }
  else if (*argument == 4)
  {
    return 1;
  }
  else
  {
    printf("Usage: pscan <host> [lower_limit] [upper_limit]\n");
    printf("host: Set the target, its mandatory!\n");
    printf("[lower_limit]: Optional to set the start port of the scan range\n");
    printf("[upper_limit]: Optional to set the end port of the scan range\n");
    printf("pscan will automatically scan the first 1024 ports if not tell otherwise.\n");
    return -1;
  }
}