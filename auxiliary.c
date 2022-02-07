#include <stdio.h>
#include "auxiliary.h"

extern int check_usage(int * argument)
{
   if(*argument != 2)
  {
    printf("pscan will automatically scan the first 1024 ports.\n");
    printf("Usage: pscan <host>\n");
    printf("No options allowed! Ignoring options typed\n");
    return -1;
  } else {
      return 0;
  }
}