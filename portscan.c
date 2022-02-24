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

// Prototypes
int print_usage(void);

int main(int argc, char const *argv[])
{

  /*** Variables ***/
  int open_ports_count = 0;
  int low_port_range = 1;
  int upper_port_range = 1024;
  int target_index = 1;
  char option;
  FILE *scan_result = NULL;

  struct sockaddr_in target;          // Struct to hold an IPv4 address + port defined in in.h
  memset(&target, sizeof(target), 0); // To zero out the struct target, to ensure there is only zeroes on that memory position
  target.sin_family = AF_INET;

  struct addrinfo request;
  memset(&request, sizeof(request), 0);
  request.ai_family = AF_INET;
  request.ai_socktype = SOCK_STREAM;

  struct addrinfo *response;

  // Inicialize the options from command line
  while ((option = getopt(argc, (char *const *)argv, "w:")) != -1)
  {
    switch (option)
    {
    case 'w':
      scan_result = fopen(optarg, "w");
      if (scan_result == NULL)
      {
        printf("\nError creating the output file. Aborting.");
        exit(EXIT_FAILURE);
      }
      break;
    }
    target_index = optind;
  }

  // Set the target
  if (isdigit(*argv[target_index])) // If its an IP address
  {
    int conv_status = inet_aton(argv[target_index], &target.sin_addr);
    if (conv_status == 0)
    {
      printf("Invalid IP address. Aborting.\n");
      exit(EXIT_FAILURE);
    }
    if (scan_result != NULL)
      fprintf(scan_result, "Open port(s) for %s: \n", inet_ntoa(target.sin_addr));
  }
  else if (isalpha(*argv[target_index])) // If its an Domain Name
  {
    int dn_resolve_status = getaddrinfo(argv[target_index], NULL, &request, &response);
    if (dn_resolve_status != 0)
    {
      struct sockaddr_in *temp_sock = (struct sockaddr_in *)response->ai_addr;
      printf("Domain name resolution failed for [%s]\n", inet_ntoa(temp_sock->sin_addr));
      exit(EXIT_FAILURE);
    }

    struct sockaddr_in *temp_sock = (struct sockaddr_in *)response->ai_addr;
    target.sin_addr = temp_sock->sin_addr;
    freeaddrinfo(response);

    if (scan_result != NULL)
      fprintf(scan_result, "Open port(s) for %s: \n", inet_ntoa(target.sin_addr));
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
      if (scan_result != NULL)
        fprintf(scan_result, "%d\n", index);
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

int print_usage(void)
{
  printf("Personal portscan (Klayton Facre - 2022)\n\n");
  printf("Usage: pscan [-rw] <target>\n");
  printf(" -r: Set the port range <lower> <upper> for the scan (optional).\n");
  printf(" -w: Set the file name <file name> to write the result (optional)\n");
  printf("pscan will automatically scan the first 1024 ports if not told otherwise.\n");

  return 0;
}