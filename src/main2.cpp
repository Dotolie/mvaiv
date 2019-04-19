#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define  BUFF_SIZE   1024

int   main( void)
{
   int   sock;
   int   client_addr_size;

   struct sockaddr_in   server_addr;
   struct sockaddr_in   client_addr;

   char   buff_rcv[BUFF_SIZE+5];
   char   buff_snd[BUFF_SIZE+5];



   sock  = socket( PF_INET, SOCK_DGRAM, 0);
   
   if( -1 == sock)
   {
      printf( "socket 생성 실패n");
      exit( 1);
   }

   memset( &server_addr, 0, sizeof( server_addr));
   server_addr.sin_family     = AF_INET;
   server_addr.sin_port       = htons( 2021);
   server_addr.sin_addr.s_addr= htonl( INADDR_ANY);

   if( -1 == bind( sock, (struct sockaddr*)&server_addr, sizeof( server_addr) ) )
   {
      printf( "bind() 실행 에러n");
      exit( 1);
   }

   while( 1)
   {
      client_addr_size  = sizeof( client_addr);
      recvfrom( sock, buff_rcv, BUFF_SIZE, 0 , 
              ( struct sockaddr*)&client_addr, (socklen_t*)&client_addr_size);
      printf( "receive: %s\r\n", buff_rcv);
      
      sprintf( buff_snd, "%s%s", buff_rcv, "+client");
      sendto( sock, buff_snd, strlen( buff_snd)+1, 0,  // +1: NULL까지 포함해서 전송
             ( struct sockaddr*)&client_addr, sizeof( client_addr)); 
   }
}

