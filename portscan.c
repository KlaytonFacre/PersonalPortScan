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

/*** GLOBALS ***/
int open_ports_count = 0;
int low_port_range = 1;
int upper_port_range = 1024;
FILE *scan_result = NULL;

struct sockaddr_in target;          // Struct to hold an IPv4 address + port defined in in.h
memset(&target, sizeof(target), 0); // To zero out the struct target, to ensure there is only zeroes on that memory position
target.sin_family = AF_INET;

struct addrinfo request;
memset(&request, sizeof(request), 0);
request.ai_family = AF_INET;
request.ai_socktype = SOCK_STREAM;

struct addrinfo *response;

/*** FUNTIONS ***/
void initialize_options(int *num_arg, char **vec_args)
{
  for (int opt_index = 1; opt_index < argc; ++opt_index)
  {
    if (strcmp(argv[opt_index], "-r") == 0) // Lets set the scan range
    {
      low_port_range = atoi(argv[++opt_index]);
      upper_port_range = atoi(argv[++opt_index]);
    }
    else if (strcmp(argv[opt_index], "-t") == 0) // Lets set the target, depending its an IP or a Domain Name
    {
      if (isdigit(*argv[opt_index + 1])) // If its an IP address
      {
        int conv_status = inet_aton(argv[++opt_index], &target.sin_addr);
        if (conv_status == 0)
        {
          printf("Invalid IP address. Aborting.\n");
          exit(EXIT_FAILURE);
        }
      }
      else if (isalpha(*argv[opt_index + 1])) // If its an Domain Name
      {
        int dn_resolve_status = getaddrinfo(argv[++opt_index], NULL, &request, &response);
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
    }
    else if (strcmp(argv[opt_index], "-w") == 0) // Lets set the file with the result of the scan
    {
      scan_result = fopen(argv[++opt_index], "w");
      if (scan_result == NULL)
      {
        printf("\nError creating the file. Aborting.");
        exit(EXIT_FAILURE);
      }
    }
    else
    {
      printf("\nUnrecognized option. Aborting.\n");
      print_usage();
      exit(EXIT_FAILURE);
    }
  }
}

int print_usage(void)
{
  printf("Personal portscan (Klayton Facre - 2022)\n\n");
  printf("Usage: pscan [-rwt] <target>\n");
  printf(" -r: Set the port range <lower> <upper> for the scan (optional).\n");
  printf(" -w: Set the file name <file name> to write the result (optional)\n");
  printf(" -t: Set the target of the scan (must have)\n\n");
  printf("pscan will automatically scan the first 1024 ports if not told otherwise.\n");

  return 0;
}

int main(int argc, char const *argv[])
{
  initialize_options(&argc, argv);

  // Lets check for the target (if its missing)
  if (target.sin_addr.s_addr == 0)
  {
    printf("\nMissing target information. Aborting.\n");
    print_usage();
    exit(EXIT_FAILURE);
  }
  else if (scan_result != NULL)
  {
    fprintf(scan_result, "Target: %s\n", inet_ntoa(target.sin_addr));
    fprintf(scan_result, "OPEN PORTS:\n");
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