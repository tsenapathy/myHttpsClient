#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>

#include "mbedtls/inc/net.h"
#include "mbedtls/inc/ssl.h"
#include "mbedtls/inc/entropy.h"
#include "mbedtls/inc/ctr_drbg.h"
#include "mbedtls/inc/debug.h"


#define SERVER_PORT 443
#define SERVER_NAME "example.com"
//#define GET_REQUEST "GET / HTTP/1.1\r\nhost: www.weevil.info\r\n\r\n"

//For the debug function to work, add a debug callback called my_debug above our main() function.
static void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
((void) level);

fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
fflush( (FILE *) ctx );

}


int main( void )
{
    int ret, len;
    unsigned char pers=0, buf[2048];
    struct sockaddr_in server_addr;
    struct hostent *server_host;

mbedtls_net_context server_fd;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;

mbedtls_net_init( &server_fd );
mbedtls_ssl_init( &ssl );
mbedtls_ssl_config_init( &conf );
//mbedtls_x509_crt_init( &cacert );
mbedtls_ctr_drbg_init( &ctr_drbg );

mbedtls_entropy_init( &entropy );
if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                  (const unsigned char *) pers,
                  strlen( pers ) ) ) != 0 )
{
   printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
   goto exit;
}


    /*
     * Start the connection
     */
    printf( "\n  . Connecting to tcp/%s/%4d...", SERVER_NAME,
                                                 SERVER_PORT );
    fflush( stdout );

/*************************    
    if( ( server_host = gethostbyname( SERVER_NAME ) ) == NULL )
    {
        printf( " failed\n  ! gethostbyname failed\n\n");
        goto exit;
    }

    if( ( server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP) ) < 0 )
    {
        printf( " failed\n  ! socket returned %d\n\n", server_fd );
        goto exit;
    }

    memcpy( (void *) &server_addr.sin_addr,
            (void *) server_host->h_addr,
                     server_host->h_length );

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons( SERVER_PORT );

    if( ( ret = connect( server_fd, (struct sockaddr *) &server_addr,
                         sizeof( server_addr ) ) ) < 0 )
    {
        printf( " failed\n  ! connect returned %d\n\n", ret );
        goto exit;
    }
***************/

if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                            SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
{
   printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
   goto exit;
}

    printf( " ok\n" );



//Prepare the SSL configuration by setting the endpoint and transport type,
//and loading reasonable defaults for the security parameters
if( ( ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) {
printf( " failed\n ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
goto exit;
}

//Set the authentication mode
mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_NONE );

//Set the random engine and debug function
mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );



//Now that the configuration is ready, set up the SSL context to use it.
if( ( ret = mbedtls_ssl_set_hostname( &ssl, "Mbed TLS Server 1" ) ) != 0 )
{
printf( " failed\n ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
goto exit;
}


//Finally, the SSL context needs to know the input and output functions it needs to use for sending out network traffic.
mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );








    /*
     * Write the GET request
     */
    printf( "  > Write to server:" );
    fflush( stdout );

//    len = sprintf( (char *) buf, GET_REQUEST );
    len = sprintf((char*)buf,"GET / HTTP/1.1\r\nHost: "SERVER_NAME"\r\n\r\n");


//    while( ( ret = write( server_fd, buf, len ) ) <= 0 )
    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret != 0 )
        {
            printf( " failed\n  ! write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s", len, (char *) buf );

    /*
     * Read the HTTP response
     */
    printf( "  < Read from server:" );
    fflush( stdout );
    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        //ret = read( server_fd, buf, len );
ret = mbedtls_ssl_read( &ssl, buf, len );



        if( ret <= 0 )
        {
            printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        len = ret;
        printf( " %d bytes read\n\n%s", len, (char *) buf );
    }while( 0 );

exit:

    //close( server_fd );
mbedtls_net_free( &server_fd );
mbedtls_ssl_free( &ssl );
mbedtls_ssl_config_free( &conf );
mbedtls_ctr_drbg_free( &ctr_drbg );
mbedtls_entropy_free( &entropy );


#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}

