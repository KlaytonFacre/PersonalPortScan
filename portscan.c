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

#include "auxiliary.h" // To hold auxiliary functions written

int main(int argc, char const *argv[])
{
  int open_ports_count = 0;
  int low_port_range;
  int upper_port_range;

  struct sockaddr_in target;          // Struct to hold an IPv4 address + port defined in in.h
  memset(&target, sizeof(target), 0); // To zero out the struct target, to ensure there is only zeroes on that memory position
  target.sin_family = AF_INET;

  struct addrinfo request;
  memset(&request, sizeof(request), 0);
  request.ai_family = AF_INET;
  request.ai_socktype = SOCK_STREAM;

  struct addrinfo *response;

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
      printf("Invalid port range. Aborting. \n");
      print_usage();
      exit(EXIT_FAILURE);
    }
    break;
  default:
    print_usage();
    exit(EXIT_FAILURE);
  }

  // Lets set the target, depending its an IP or a Domain Name
  if (isdigit(*argv[1])) // If its an IP address
  {
    int conv_status = inet_aton(argv[1], &target.sin_addr);
    if (conv_status == 0)
    {
      printf("Invalid IP address. Aborting.\n");
      exit(EXIT_FAILURE);
    }
  }
  else if (isalpha(*argv[1])) // If its an Domain Name
  {
    int dn_resolve_status = getaddrinfo(argv[1], NULL, &request, &response);
    if (dn_resolve_status != 0)
    {
      struct sockaddr_in *temp_sock = (struct sockaddr_in *)response->ai_addr;
      printf("Domain name resolution failed. [%s]\n", inet_ntoa(temp_sock->sin_addr));
      exit(EXIT_FAILURE);
    }

    struct sockaddr_in *temp_sock = (struct sockaddr_in *)response->ai_addr;
    target.sin_addr = temp_sock->sin_addr;
    freeaddrinfo(response);
  }
  else // If its none of the above
  {
    perror("Target: ");
    exit(EXIT_FAILURE);
  }

  /* Here the scan starts */
  printf("\nScaning [%s]\n", inet_ntoa(target.sin_addr));

  for (int index = low_port_range; index <= upper_port_range; ++index) // Actual scanning start
  {
    target.sin_port = htons(index); // Set the port that is gonna be scanned right now in the correct byte order for this host

    int stream_socket = socket(AF_INET, SOCK_STREAM, 0); // Create a socket for TCP/IP 4 connection
    if (stream_socket == -1)                             // Check for socket erros on the socket() call above
    {
      perror("socket: ");
      return (EXIT_FAILURE);
    }

    int conn_status = connect(stream_socket, (struct sockaddr *)&target, sizeof(struct sockaddr_in));
    if (conn_status == 0)
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

  printf("\nResults: %d port(s) open on target %s\n", open_ports_count, inet_ntoa(target.sin_addr));
  return (EXIT_SUCCESS);
}