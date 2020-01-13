#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#define MBEDTLS_CONFIG_FILE "config.h"


#include "inc/mbedtls/net.h"
#include "inc/mbedtls/net_sockets.h"
#include "inc/mbedtls/ssl.h"
#include "inc/mbedtls/entropy.h"
#include "inc/mbedtls/ctr_drbg.h"
#include "inc/mbedtls/debug.h"
#include "inc/mbedtls/certs.h"
#include "inc/mbedtls/x509_crt.h"

#include <string.h>
#define mbedtls_printf printf
#define SERVER_PORT "443"
#define SERVER_NAME "google.com"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"


//For the debug function to work, add a debug callback called my_debug above our main() function.
static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
((void) level);

fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
fflush( (FILE *) ctx );

}


int main( void )
{
    int ret = 1, len;
    struct sockaddr_in server_addr;
    struct hostent *server_host;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[1024];
    const char *pers="hworld_tls";


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;

mbedtls_net_init( &server_fd );
mbedtls_ssl_init( &ssl );
mbedtls_ssl_config_init( &conf );
mbedtls_x509_crt_init( &cacert );
mbedtls_ctr_drbg_init( &ctr_drbg );

    printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
mbedtls_entropy_init( &entropy );
if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                  (const unsigned char *) pers,
                  strlen( pers ) ) ) != 0 )
{
   printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
   goto exit;
}

    printf( " ok\n" );

    /*
     * Start the connection
     */
    printf( "  . Loading the CA root certificate ..." );
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
    ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) mbedtls_test_cas_pem,
                          mbedtls_test_cas_pem_len );
    if( ret < 0 )
    {
        printf( " failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret );
        goto exit;
    }

    printf( " ok (%d skipped)\n", ret );
    printf( " ok\n" );
    /*
     * 1. Start the connection
     */
    printf( "\n  . Connecting to tcp/%s/%4d...", SERVER_NAME,
                                                 SERVER_PORT );

    fflush( stdout );
	
if( ( ret = mbedtls_net_connect( &server_fd, SERVER_NAME,
                            SERVER_PORT, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
{
   printf( " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
   goto exit;
}

    printf( " ok\n" );



//Prepare the SSL configuration by setting the endpoint and transport type,
//and loading reasonable defaults for the security parameters

    printf( "  . Setting up the SSL/TLS structure..." );
    fflush( stdout );
	
if( ( ret = mbedtls_ssl_config_defaults( &conf, 
			MBEDTLS_SSL_IS_CLIENT, 
			MBEDTLS_SSL_TRANSPORT_STREAM, 
			MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 ) 
{
printf( " failed\n ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
goto exit;
}

    printf( " ok\n" );
//Set the authentication mode
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );

    printf( " authmode ok\n" );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
	
//Set the random engine and debug function
mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    printf( "mbedtls_ssl_conf_rng ok\n" );
mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    printf( "mbedtls_ssl_conf_dbg ok\n" );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto exit;
    }
	printf( "mbedtls_ssl_setup ok\n" );
//Now that the configuration is ready, set up the SSL context to use it.
    if( ( ret = mbedtls_ssl_set_hostname( &ssl, SERVER_NAME ) ) != 0 )
{
printf( " failed\n ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
goto exit;
}
	printf( "mbedtls_ssl_set_hostname ok\n" );


//Finally, the SSL context needs to know the input and output functions it needs to use for sending out network traffic.
mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 4. Handshake
     */
    printf( "  . Performing the SSL/TLS handshake..." );
    fflush( stdout );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
            goto exit;
        }
    }

    mbedtls_printf( " ok\n" );

    /*
     * 5. Verify the server certificate
     */
    printf( "  . Verifying peer X.509 certificate..." );

    /* In real life, we probably want to bail out when ret != 0 */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];

        printf( " failed\n" );

        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );

        printf( "%s\n", vrfy_buf );
    }
    else
        printf( " ok\n" );

    /*
     * Write the GET request
     */
    printf( "  > Write to server:" );
    fflush( stdout );

    len = sprintf( (char *) buf, GET_REQUEST );
  //  len = sprintf((char*)buf,"GET / HTTP/1.1\r\nHost: "SERVER_NAME"\r\n\r\n");


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

    mbedtls_ssl_close_notify( &ssl );
exit:

    //close( server_fd );
mbedtls_net_free( &server_fd );
    mbedtls_x509_crt_free( &cacert );
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

