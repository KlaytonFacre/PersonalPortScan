/*
* Port scan projetado conforme vídeo no youtube
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

int main(int argc, char const *argv[]) {
  if(argc != 2)
  {
    printf("pscan will automatically scan the first 1024 ports.\n");
    printf("Usage: pscan <host>\n");
    return -1;
  }

  struct sockaddr_in remote;          // Struct to hold an IPv4 address + port
  struct hostent *host;               // To hold an Hostname info and resolve it to IPv4

  int sfd = socket(AF_INET, SOCK_STREAM, 0);    // Create a socket for TCP/IP 4 connection
  if(sfd < 0)
  {
    perror("socket: ");
    return -1;
  }

  memset(&remote, sizeof(remote), 0);   // To zero out the struct remote, to ensure there is only zeroes on that memory position
  remote.sin_family = AF_INET;


  host = gethostbyname(argv[1]);    // Resolve an domain name to IPv4
  if(host == NULL)
  {
    perror("Get host by name: ");
    return -1;
  }
  remote.sin_addr.s_addr = *(unsigned long *) host->h_addr;

  for(int index = 1; index < 1024; ++index)
  {
    remote.sin_port = htons(index);
    int ret = connect(sfd, (struct sockaddr *) &remote, sizeof(struct sockaddr_in));
    if(ret < 0)
    {
      perror("connect: ");
    }
    else
    {
      printf("Port %d open\n", index);
    }
    close(sfd);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sfd < 0)
    {
      perror("socket: ");
      return -1;
    }
  }

  return 0;
}
