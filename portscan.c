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
#include <ctype.h>

#include "auxiliary.h" // To house auxiliary functions written

int main(int argc, char const *argv[])
{
  int open_ports_count = 0;
  int low_port_range;                 // In case of use a port range to scan
  int upper_port_range;               // In case of use a port range to scan
  struct sockaddr_in target;          // Struct to hold an IPv4 address + port defined in in.h
  memset(&target, sizeof(target), 0); // To zero out the struct target, to ensure there is only zeroes on that memory position
  target.sin_family = AF_INET;

  // check for pscan <host> <low_port> <upper_port>
  switch (argc)
  {
  case 2: // In case of pscan <target>, set the default port range
    low_port_range = 1;
    upper_port_range = 1024;
    if (isdigit(argv[1]))
    {
      inet_aton(argv[1], &target.sin_addr);
    }
    else
    {
      perror("Target: ");
      exit(2);
    }
    break;
  case 4: // In case of pscan <target> [low_range] [upper_range]
    low_port_range = atoi(argv[2]);
    upper_port_range = atoi(argv[3]);
    if(isdigit(argv[1]))
    {
      inet_aton(argv[1], &target.sin_addr);
    }
    else
    {
      perror("Target: ");
      exit(2);
    }
    break;
  default:
    print_usage();
    exit(1);
  }

  /*
  struct hostent *name;                                       // To hold an Hostname info and resolve it to IPv4
  name = gethostbyname(argv[1]);                              // Resolve an domain name to IPv4
  if (name == NULL)
  {
    perror("Get host by name: ");
    return -1;
  }
  target.sin_addr.s_addr = *(unsigned long *)name->h_addr;
  */

  printf("\nSCANNING...\n");

  for (int index = low_port_range; index <= upper_port_range; ++index) // Actual scanning start
  {
    target.sin_port = htons(index); // Set the port that is gonna be scanned right now

    int stream_socket = socket(AF_INET, SOCK_STREAM, 0); // Create a socket for TCP/IP 4 connection
    if (stream_socket == -1)                             // Check for socket erros on the socket() call above
    {
      perror("socket: ");
      return -1;
    }

    int result = connect(stream_socket, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
    if (result == 0)
    {
      printf("[Port %d: Open]\n", index);
      ++open_ports_count;
    }
    else
    {
      printf("[Port %d: Closed]\n", index);
    }

    close(stream_socket);
  }

  printf("\nResults: %d port(s) open on host.\n", open_ports_count);
  return 0;
}