/*
 * Port scan created based on youtube video
 * https://youtu.be/4Q0jH1zjvfc
 * Code by: Klayton Facre - 29 JAN 2022
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "auxiliary.h"                                        // To house auxiliary functions written

int main(int argc, char const *argv[])
{
  int low_port_range;                                         // In case of use a port range to scan
  int upper_port_range;                                       // In case of use a port range to scan

  int usage = check_usage(&argc);                             // check for pscan <host> <low_port> <upper_port>
  switch (usage)
  {
  case 0:                                                     // In case of pscan <target>
    low_port_range = 1;
    upper_port_range = 1024;
    break;
  case 1:                                                     // In case of pscan <target> [low_range] [upper_range]
    low_port_range = atoi(argv[2]);
    upper_port_range = atoi(argv[3]);
    break;
  default:
    exit(-1);
  }

  int open_ports_count = 0;
  struct sockaddr_in target;                                  // Struct to hold an IPv4 address + port defined in in.h
  struct hostent *name;                                       // To hold an Hostname info and resolve it to IPv4

  int stream_socket = socket(AF_INET, SOCK_STREAM, 0);        // Create a socket for TCP/IP 4 connection
  if (stream_socket == -1)
  {
    perror("socket: ");
    return -1;
  }

  memset(&target, sizeof(target), 0);                         // To zero out the struct target, to ensure there is only zeroes on that memory position
  target.sin_family = AF_INET;

  name = gethostbyname(argv[1]);                              // Resolve an domain name to IPv4
  if (name == NULL)
  {
    perror("Get host by name: ");
    return -1;
  }
  target.sin_addr.s_addr = *(unsigned long *)name->h_addr;

  printf("\nSCANNING...\n");

  for (int index = low_port_range; index < upper_port_range; ++index)
  {
    target.sin_port = htons(index);
    int ret = connect(stream_socket, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
    if (ret == 0)
    {
      printf("[Port %d open]\n", index);
      ++open_ports_count;
    }
    else
    {
      printf("[Port %d is closed]\n", index);
    }

    close(stream_socket);
    stream_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (stream_socket < 0)
    {
      perror("socket: ");
      return -1;
    }
  }

  printf("\nResults: %d port(s) open on host.\n", open_ports_count);
  return 0;
}
