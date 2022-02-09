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
  int low_port_range;   // In case of use a port range to scan
  int upper_port_range; // In case of use a port range to scan

  struct sockaddr_in target;          // Struct to hold an IPv4 address + port defined in in.h
  memset(&target, sizeof(target), 0); // To zero out the struct target, to ensure there is only zeroes on that memory position
  target.sin_family = AF_INET;

  struct addrinfo request;
  memset(&request, sizeof(request), 0);
  request.ai_family = AF_INET;
  request.ai_socktype = SOCK_STREAM;

  struct addrinfo *response;
  char ipstr[INET6_ADDRSTRLEN];

  // Lets set the corret range depending of the command line arguments
  switch (argc)
  {
  case 2: // In case of pscan <target>, set the default port range
    low_port_range = 1;
    upper_port_range = 1024;
    break;
  case 4: // In case of pscan <target> [low_range] [upper_range], set the apropriate range
    if (isdigit(*argv[2]) && isdigit(*argv[3]))
    {
      low_port_range = atoi(argv[2]);
      upper_port_range = atoi(argv[3]);
    }
    else
    {
      print_usage();
      exit(1);
    }
    break;
  default:
    print_usage();
    exit(1);
  }

  // Lets set the target, depending its an IP or a Domain Name
  if (isdigit(*argv[1])) // If its an IP address
  {
    inet_aton(argv[1], &target.sin_addr);
  }
  else if (getaddrinfo(argv[1], NULL, &request, &response) == 0) // If its an Domain Name
  {
    inet_ntop(AF_INET, response[0].ai_addr, ipstr, sizeof(ipstr));
    inet_aton(ipstr, &target.sin_addr);
    printf("%s\n", ipstr);
    freeaddrinfo(response);
  }
  else // If its none of the above
  {
    perror("Target: ");
    exit(2);
  }

  /* Here the scan starts */
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

  printf("\nResults: %d port(s) open on target %s [%s].\n", open_ports_count, argv[1], ipstr);
  return 0;
}