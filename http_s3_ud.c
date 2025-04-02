#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "s3_config.h"
#include "http_s3_utils.h"
#include "core_http_client.h"
#include "mbedtls/sha256.h"
#include "network_transport.h"
#include "core_json.h"
#include "sigv4.h"
#include "mbedtls/sha256.h"
#include "backoff_algorithm.h"
#include "common_hdr.h"
#include "http_s3_ud.h"

#define USER_BUFFER_LENGTH    ( 4096 )

/**
 * @brief The length of the HTTP GET method.
 */
#define HTTP_METHOD_GET_LENGTH                    ( sizeof( HTTP_METHOD_GET ) - 1 )

/**
 * @brief Field name of the HTTP Range header to read from server response.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD           "Content-Range"

/**
 * @brief Length of the HTTP Range header field.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD_LENGTH    ( sizeof( HTTP_CONTENT_RANGE_HEADER_FIELD ) - 1 )

/**
 * @brief HTTP status code returned for partial content.
 */
#define HTTP_STATUS_CODE_PARTIAL_CONTENT          206

/**
 * @brief Length of the pre-signed PUT URL defined in demo_config.h.
 */
#define S3_PRESIGNED_PUT_URL_LENGTH               ( sizeof( S3_PRESIGNED_PUT_URL ) - 1 )

/**
 * @brief Length of the pre-signed GET URL defined in demo_config.h.
 */
#define S3_PRESIGNED_GET_URL_LENGTH               ( sizeof( S3_PRESIGNED_GET_URL ) - 1 )

/**
 * @brief Field name of the HTTP Range header to read from server response.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD           "Content-Range"

/**
 * @brief Length of the HTTP Range header field.
 */
#define HTTP_CONTENT_RANGE_HEADER_FIELD_LENGTH    ( sizeof( HTTP_CONTENT_RANGE_HEADER_FIELD ) - 1 )

/**
 * @brief The length of the HTTP GET method.
 */
#define HTTP_METHOD_GET_LENGTH                    ( sizeof( HTTP_METHOD_GET ) - 1 )

/**
 * @brief The length of the HTTP PUT method.
 */
#define HTTP_METHOD_PUT_LENGTH                    ( sizeof( HTTP_METHOD_PUT ) - 1 )

#define UPLOAD_MAX_RETRIES_LOOP_COUNT           ( 3 )

#define DOWNLOAD_MAX_RETRIES_LOOP_COUNT         ( 3000 )

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S    ( 5 )

/**
 * @brief Buffer Length for storing the AWS IoT Credentials retrieved from
 * AWS IoT credential provider which includes the following:
 * 1. Access Key ID
 * 2. Secret Access key
 * 3. Session Token
 * 4. Expiration Date
 */
#define CREDENTIAL_BUFFER_LENGTH                 1500U

/**
 * @brief The length in bytes of the user buffer.
 *
 * @note A portion of the user buffer will be used to store the response header,
 * so the length of the response body returned on any given range request will
 * be less than USER_BUFFER_LENGTH. We don't expect S3 to send more than 1024
 * bytes of headers.
 */
#define USER_BUFFER_LENGTH                      ( 4096 )

/**
 * @brief The size of the range of the file to download, with each request.
 *
 * @note This should account for the response headers that will also be stored
 * in the user buffer. We don't expect S3 to send more than 1024 bytes of
 * headers.
 */
#define RANGE_REQUEST_LENGTH                    ( 2048 )

/**
 * @brief The URI path for HTTP requests to AWS IoT Credential provider.
 */
#define AWS_IOT_CREDENTIAL_PROVIDER_URI_PATH \
    "/role-aliases/"                         \
    AWS_IOT_CREDENTIAL_PROVIDER_ROLE "/credentials"

/**
 * @brief HTTP header name for specifying the IOT Thing resource name in request to AWS S3.
 */
#define AWS_IOT_THING_NAME_HEADER_FIELD               "x-amz-iot-thing-name"

/**
 * @brief Field name of the HTTP date header to read from the AWS IOT credential provider server response.
 */
#define AWS_IOT_CRED_PROVIDER_RESPONSE_DATE_HEADER    "date"

/**
 * @brief Field name of the HTTP Authorization header to add to the request headers.
 */
#define SIGV4_AUTH_HEADER_FIELD_NAME                  "Authorization"

/**
 * @brief Length of AWS HTTP Authorization header value generated using SigV4 library.
 */
#define AWS_HTTP_AUTH_HEADER_VALUE_LEN                2048U

/**
 * @brief Maximum Length for AWS IOT Credential provider server host name.
 *
 * @note length of the AWS IOT Credential provider server host name string
 * cannot exceed this value.
 */
#define SERVER_HOST_NAME_MAX_LENGTH                   65U

/**
 * @brief Access Key Id key to be searched in the IoT credentials response.
 */
#define CREDENTIALS_RESPONSE_ACCESS_KEY_ID_KEY        "credentials.accessKeyId"

/**
 * @brief Secret Access key to be searched in the IoT credentials response.
 */
#define CREDENTIALS_RESPONSE_SECRET_ACCESS_KEY        "credentials.secretAccessKey"

/**
 * @brief Session Token key to be searched in the IoT credentials response.
 */
#define CREDENTIALS_RESPONSE_SESSION_TOKEN_KEY        "credentials.sessionToken"

/**
 * @brief Expiration Date key to be searched in the IoT credentials response.
 */
#define CREDENTIALS_RESPONSE_EXPIRATION_DATE_KEY      "credentials.expiration"

/**
 * @brief Represents empty payload for HTTP GET request sent to AWS S3.
 */
#define S3_REQUEST_EMPTY_PAYLOAD                      ""

/**
 * @brief ALPN protocol name to be sent as part of the ClientHello message.
 *
 * @note When using ALPN, port 443 must be used to connect to AWS IoT Core.
 */
#define IOT_CORE_ALPN_PROTOCOL_NAME    "x-amzn-http-ca"

/**
 * @brief Static buffer for TLS Context Semaphore.
 */
static StaticSemaphore_t xTlsContextSemaphoreBuffer;

extern const char root_cert_auth_start[] asm("_binary_root_cert_auth_pem_start");
extern const char root_cert_auth_end[]   asm("_binary_root_cert_auth_pem_end");

/* Check that a path for the client certificate is defined. */

extern const char client_cert_start[] asm("_binary_client_crt_start");
extern const char client_cert_end[] asm("_binary_client_crt_end");
extern const char client_key_start[] asm("_binary_client_key_start");
extern const char client_key_end[] asm("_binary_client_key_end");

extern const char ca_cert_aws_s3_start[] asm("_binary_ca_cert_aws_s3_pem_start");
extern const char ca_cert_aws_s3_end[]   asm("_binary_ca_cert_aws_s3_pem_end");

/**
 * @brief A buffer used in the demo for storing HTTP request headers and HTTP
 * response headers and body.
 *
 * @note This demo shows how the same buffer can be re-used for storing the HTTP
 * response after the HTTP request is sent out. However, the user can decide how
 * to use buffers to store HTTP requests and responses.
 */
static uint8_t userBuffer[ USER_BUFFER_LENGTH ];

/**
 * @brief The pre-signed PUT URL 
 */

#define AWS_S3_URL_LENGTH  4096

static char s3Url[ AWS_S3_URL_LENGTH ] = {0};

/**
 * @brief Represents header data that will be sent in an HTTP request.
 */
static HTTPRequestHeaders_t requestHeaders;

/**
 * @brief Configurations of the initial request headers that are passed to
 * #HTTPClient_InitializeRequestHeaders.
 */
static HTTPRequestInfo_t requestInfo;

/**
 * @brief Represents a response returned from an HTTP server.
 */
static HTTPResponse_t response;

/**
 * @brief The location of the path within the server URL.
 */
static const char * pPath;

/**
 *  @brief mbedTLS Hash Context passed to SigV4 cryptointerface for generating the hash digest.
 */
static mbedtls_sha256_context hashContext = { 0 };

/**
 *  @brief Configurations of the AWS credentials sent to sigV4 library for generating the Authorization Header.
 */
static SigV4Credentials_t sigvCreds = { 0 };

/**
 * @brief Represents a response returned from an AWS IOT credential provider.
 */
static HTTPResponse_t credentialResponse = { 0 };

/**
 * @brief Buffer used in the demo for storing temporary credentials
 * received from AWS TOT credential provider.
 */
static uint8_t pAwsIotHttpBuffer[ CREDENTIAL_BUFFER_LENGTH ] = { 0 };

/**
 * @brief Represents date in ISO8601 format used in the HTTP requests sent to AWS S3.
 */
static char pDateISO8601[ SIGV4_ISO_STRING_LEN ] = { 0 };

/**
 * @brief Represents hash digest of payload.
 */
static char pPayloadHashDigest[ SHA256_HASH_DIGEST_LENGTH ];

/**
 * @brief Represents hex encoded hash digest of payload.
 */
static char hexencoded[ HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH ];

/**
 * @brief Represents Authorization header value generated using SigV4 library.
 */
static char pSigv4Auth[ AWS_HTTP_AUTH_HEADER_VALUE_LEN ];

/**
 * @brief Represents Length of Authorization header value generated using SigV4 library.
 */
static size_t sigv4AuthLen = AWS_HTTP_AUTH_HEADER_VALUE_LEN;

/**
 * @brief The security token retrieved from AWS IoT credential provider
 * required for making HTTP requests to AWS S3.
 */
static const char * pSecurityToken;

/**
 * @brief Length of security token retrieved from AWS IoT credential provider
 * required for making HTTP requests to AWS S3.
 */
static size_t securityTokenLen;

/**
 * @brief The expiration time for the temporary credentials retrieved
 * from AWS IoT credential provider service.
 */
static const char * pExpiration;

/**
 * @brief Length of expiration time for the temporary credentials retrieved
 * from AWS IoT credential provider service.
 */
static size_t expirationLen;

static char serverHost[ SERVER_HOST_NAME_MAX_LENGTH ];

static size_t serverHostLength;  

static size_t downloadCurByteTracking = 0;

static size_t downloadFileSizeTotal = 0;

static uint16_t downloadResponseStatusCode = 0;

static bool aws_s3_exit = false;

static lfs2_file_t     x_local_file;

static void local_file_init(const char *file_name, bool need_truncate)
{
    if(need_truncate)
    {
        if (lfs2_file_open (g_px_lfs2, &x_local_file, file_name, LFS2_O_RDWR | LFS2_O_CREAT | LFS2_O_TRUNC) < 0)
        {
            LogError(("Failed to open file for writing"));
        }
    }
    else{
        if (lfs2_file_open (g_px_lfs2, &x_local_file, file_name, LFS2_O_RDWR) < 0)
        {
            LogError(("Failed to open file for writing"));
        }
    }
}

static void local_file_write(const uint8_t *data, int len)
{
    if (lfs2_file_write (g_px_lfs2, &x_local_file, data, len) != len)
    {
        LogError(("Failed to write file"));
    }
}

static void local_file_read(const uint8_t **data, int *len)
{
    lfs2_soff_t file_size = lfs2_file_size(g_px_lfs2, &x_local_file); 
    
    char *content = (char *) malloc(file_size);
    if (lfs2_file_read(g_px_lfs2, &x_local_file, content, file_size) < 0)
    {
        LogError(("Failed to read file"));
    }
    *data = (const uint8_t *)content;
    *len = file_size;
}

static void local_file_close(void)
{
    lfs2_file_close (g_px_lfs2, &x_local_file) ;
}

void aws_s3_ops_exit(void)
{
    aws_s3_exit = true;
}

static void cleanEnv(void)
{
    sigv4AuthLen = AWS_HTTP_AUTH_HEADER_VALUE_LEN;
    memset(pSigv4Auth, 0, AWS_HTTP_AUTH_HEADER_VALUE_LEN);
    memset(userBuffer, 0, USER_BUFFER_LENGTH);
    downloadCurByteTracking = 0;
    downloadResponseStatusCode = 0;
    aws_s3_exit = false;
}
/**
 * @brief CryptoInterface provided to SigV4 library for generating the hash digest.
 */
static SigV4CryptoInterface_t cryptoInterface =
{
    .hashInit      = sha256Init,
    .hashUpdate    = sha256Update,
    .hashFinal     = sha256Final,
    .pHashContext  = &hashContext,
    .hashBlockLen  = HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH,
    .hashDigestLen = SHA256_HASH_DIGEST_LENGTH,
};

/**
 * @brief SigV4 parameters provided to SigV4 library by the application for generating
 * the Authorization header.
 */
static SigV4Parameters_t sigv4Params =
{
    .pCredentials     = &sigvCreds,
    .pDateIso8601     = pDateISO8601,
    .pRegion          = AWS_S3_BUCKET_REGION,
    .regionLen        = sizeof( AWS_S3_BUCKET_REGION ) - 1,
    .pService         = AWS_S3_SERVICE_NAME,
    .serviceLen       = sizeof( AWS_S3_SERVICE_NAME ) - 1,
    .pCryptoInterface = &cryptoInterface,
    .pHttpParameters  = NULL
};

/************************************************************************************* */

static bool downloadS3ObjectFile( const TransportInterface_t * pTransportInterface,
                                  const char * pPath );
static bool getS3ObjectFileSize( size_t * pFileSize,
                                 const TransportInterface_t * pTransportInterface,
                                 const char * pHost,
                                 size_t hostLen,
                                 const char * pPath );

static JSONStatus_t parseCredentials( HTTPResponse_t * response,
                                      SigV4Credentials_t * sigvCreds );

static bool getTemporaryCredentials( TransportInterface_t * transportInterface,
                                     char * pDateISO8601,
                                     size_t pDateISO8601Len,
                                     HTTPResponse_t * response,
                                     SigV4Credentials_t * sigvCreds );

static void getHeaderStartLocFromHttpRequest( HTTPRequestHeaders_t requestHeaders,
                                              char ** pStartHeaderLoc,
                                              size_t * pHeadersDataLen );


static JSONStatus_t parseCredentials( HTTPResponse_t * response,
                                      SigV4Credentials_t * sigvCreds )
{
    JSONStatus_t jsonStatus = JSONSuccess;

    assert( response != NULL );
    assert( sigvCreds != NULL );

    if( jsonStatus == JSONSuccess )
    {
        /* Get accessKeyId from HTTP response. */
        jsonStatus = JSON_Search( ( char * ) response->pBody,
                                  response->bodyLen,
                                  CREDENTIALS_RESPONSE_ACCESS_KEY_ID_KEY,
                                  strlen( CREDENTIALS_RESPONSE_ACCESS_KEY_ID_KEY ),
                                  ( char ** ) &( sigvCreds->pAccessKeyId ),
                                  &( sigvCreds->accessKeyIdLen ) );

        if( jsonStatus != JSONSuccess )
        {
            LogError( ( "Error parsing accessKeyId in the credentials." ) );
        }
    }

    if( jsonStatus == JSONSuccess )
    {
        /* Get secretAccessKey from HTTP response. */
        jsonStatus = JSON_Search( ( char * ) response->pBody,
                                  response->bodyLen,
                                  CREDENTIALS_RESPONSE_SECRET_ACCESS_KEY,
                                  strlen( CREDENTIALS_RESPONSE_SECRET_ACCESS_KEY ),
                                  ( char ** ) &( sigvCreds->pSecretAccessKey ),
                                  &( sigvCreds->secretAccessKeyLen ) );

        if( jsonStatus != JSONSuccess )
        {
            LogError( ( "Error parsing secretAccessKey in the credentials." ) );
        }
    }

    if( jsonStatus == JSONSuccess )
    {
        /* Get sessionToken from HTTP response. */
        jsonStatus = JSON_Search( ( char * ) response->pBody,
                                  response->bodyLen,
                                  CREDENTIALS_RESPONSE_SESSION_TOKEN_KEY,
                                  strlen( CREDENTIALS_RESPONSE_SESSION_TOKEN_KEY ),
                                  ( char ** ) &( pSecurityToken ),
                                  &( securityTokenLen ) );

        if( jsonStatus != JSONSuccess )
        {
            LogError( ( "Error parsing sessionToken in the credentials." ) );
        }
    }

    if( jsonStatus == JSONSuccess )
    {
        /* Get expiration date from HTTP response. */
        jsonStatus = JSON_Search( ( char * ) response->pBody,
                                  response->bodyLen,
                                  CREDENTIALS_RESPONSE_EXPIRATION_DATE_KEY,
                                  strlen( CREDENTIALS_RESPONSE_EXPIRATION_DATE_KEY ),
                                  ( char ** ) &( pExpiration ),
                                  &( expirationLen ) );

        if( jsonStatus != JSONSuccess )
        {
            LogError( ( "Error parsing expiration date in the credentials." ) );
        }
        else
        {
            LogInfo( ( "AWS IoT credentials will expire after this timestamp: %.*s.", ( int ) expirationLen, pExpiration ) );
        }
    }

    return jsonStatus;
}

static bool getTemporaryCredentials( TransportInterface_t * transportInterface,
                                     char * pDateISO8601,
                                     size_t pDateISO8601Len,
                                     HTTPResponse_t * response,
                                     SigV4Credentials_t * sigvCreds )
{
    bool returnStatus = true;
    HTTPRequestHeaders_t requestHeaders = { 0 };
    HTTPRequestInfo_t requestInfo = { 0 };
    size_t pathLen = 0;
    size_t addressLen = 0;
    HTTPStatus_t httpStatus = HTTPSuccess;
    SigV4Status_t sigv4Status = SigV4Success;
    JSONStatus_t jsonStatus = JSONSuccess;
    const char * pAddress = NULL;
    const char * pDate = NULL;
    const char * pPath = NULL;
    size_t dateLen = 0;

    assert( transportInterface != NULL );
    assert( response != NULL );
    assert( sigvCreds != NULL );
    assert( pDateISO8601 != NULL );
    assert( pDateISO8601Len > 0 );

    pAddress = AWS_IOT_CREDENTIAL_PROVIDER_ENDPOINT;
    addressLen = strlen( AWS_IOT_CREDENTIAL_PROVIDER_ENDPOINT );

    pPath = AWS_IOT_CREDENTIAL_PROVIDER_URI_PATH;
    pathLen = strlen( AWS_IOT_CREDENTIAL_PROVIDER_URI_PATH );

    /* Initialize Request header buffer. */
    requestHeaders.pBuffer = response->pBuffer;
    requestHeaders.bufferLen = response->bufferLen;

    /* Set HTTP request parameters to get temporary AWS IoT credentials. */
    requestInfo.pMethod = HTTP_METHOD_GET;
    requestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = pathLen;
    requestInfo.pHost = pAddress;
    requestInfo.hostLen = addressLen;
    requestInfo.reqFlags = 0;

    response->pHeaderParsingCallback = NULL;

    if( returnStatus == true )
    {
        /* Initialize request headers. */
        httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders, &requestInfo );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to initialize request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Add AWS_IOT_THING_NAME_HEADER_FIELD header to the HTTP request headers. */
        httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                           AWS_IOT_THING_NAME_HEADER_FIELD,
                                           sizeof( AWS_IOT_THING_NAME_HEADER_FIELD ) - 1U,
                                           AWS_IOT_THING_NAME,
                                           sizeof( AWS_IOT_THING_NAME ) - 1U );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add x-amz-iot-thing-name header to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Send the request to AWS IoT Credentials Provider to obtain temporary credentials
         * so that the demo application can access configured S3 bucket thereafter. */
        httpStatus = HTTPClient_Send( transportInterface,
                                      &requestHeaders,
                                      NULL,
                                      0,
                                      response, 0 );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to send HTTP GET request to %s%s  for obtaining temporary credentials: Error=%s.",
                        pAddress, pPath, HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Parse the credentials received in the response. */
        jsonStatus = parseCredentials( response, sigvCreds );

        LogDebug( ( "AWS IoT credential provider response: %.*s.",
                    ( int32_t ) response->bufferLen, response->pBuffer ) );

        if( jsonStatus != JSONSuccess )
        {
            LogError( ( "Failed to parse temporary IoT credentials retrieved from AWS IoT credential provider" ) );
            returnStatus = false;
        }
    }

    /* Get the AWS IoT date from the http response. */
    if( returnStatus == true )
    {
        httpStatus = HTTPClient_ReadHeader( response,
                                            AWS_IOT_CRED_PROVIDER_RESPONSE_DATE_HEADER,
                                            sizeof( AWS_IOT_CRED_PROVIDER_RESPONSE_DATE_HEADER ) - 1,
                                            ( const char ** ) &pDate,
                                            &dateLen );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to retrieve \"%s\" header from response: Error=%s.",
                        AWS_IOT_CRED_PROVIDER_RESPONSE_DATE_HEADER, HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Convert AWS IoT date retrieved from IoT server to ISO 8601 date format. */
        sigv4Status = SigV4_AwsIotDateToIso8601( pDate, dateLen, pDateISO8601, pDateISO8601Len );

        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Failed to convert AWS IoT date to ISO 8601 format." ) );
            returnStatus = false;
        }
    }

    return returnStatus;
}

static void getHeaderStartLocFromHttpRequest( HTTPRequestHeaders_t requestHeaders,
                                              char ** pStartHeaderLoc,
                                              size_t * pHeadersDataLen )
{
    size_t headerLen = requestHeaders.headersLen;
    char * pHeaders = ( char * ) requestHeaders.pBuffer;
    bool newLineFound = false;

    assert( pStartHeaderLoc != NULL );
    assert( pHeadersDataLen != NULL );

    while( headerLen >= 2 )
    {
        if( 0 == strncmp( pHeaders, "\r\n", strlen( "\r\n" ) ) )
        {
            newLineFound = true;
            break;
        }

        pHeaders++;
        headerLen--;
    }

    if( newLineFound == false )
    {
        LogError( ( "Failed to find starting location of HTTP headers in HTTP request: \"\\r\\n\" missing before start of HTTP headers." ) );
    }

    assert( newLineFound != false );

    /* Moving header pointer past "\r\n" .*/
    *pHeadersDataLen = headerLen - 2;
    *pStartHeaderLoc = pHeaders + 2;
}

static int32_t connectToIotServer( NetworkContext_t * pNetworkContext )
{
    int32_t returnStatus = EXIT_FAILURE;

    /* Status returned by transport implementation. */
    TlsTransportStatus_t tlsStatus;

    /* Initialize TLS credentials. */
    pNetworkContext->pcHostname = AWS_IOT_CREDENTIAL_PROVIDER_ENDPOINT;
    pNetworkContext->xPort = HTTPS_PORT;
    pNetworkContext->pxTls = NULL;
    pNetworkContext->xTlsContextSemaphore = xSemaphoreCreateMutexStatic(&xTlsContextSemaphoreBuffer);
    //client cert
    pNetworkContext->pcClientCert = client_cert_start;
    pNetworkContext->pcClientCertSize = client_cert_end - client_cert_start;
    //private key
    pNetworkContext->pcClientKey = client_key_start;
    pNetworkContext->pcClientKeySize = client_key_end - client_key_start;
    //rootCA
    pNetworkContext->pcServerRootCA = root_cert_auth_start;
    pNetworkContext->pcServerRootCASize = root_cert_auth_end - root_cert_auth_start;

    pNetworkContext->disableSni = 1;

    if( HTTPS_PORT == 443 )
    {
        static const char * pcAlpnProtocols[] = { NULL, NULL };
        pcAlpnProtocols[0] = IOT_CORE_ALPN_PROTOCOL_NAME;
        pNetworkContext->pAlpnProtos = pcAlpnProtocols;

    } else {
         pNetworkContext->pAlpnProtos = NULL;
    }

    LogInfo( ( "Establishing a TLS session to %.*s:%d.",
               strlen( AWS_IOT_CREDENTIAL_PROVIDER_ENDPOINT ),
               AWS_IOT_CREDENTIAL_PROVIDER_ENDPOINT,
               HTTPS_PORT ) );

    tlsStatus = xTlsConnect ( pNetworkContext );

    if( tlsStatus == TLS_TRANSPORT_SUCCESS )
    {
        returnStatus = EXIT_SUCCESS;
    }
    else
    {
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int32_t connectToS3( NetworkContext_t * pNetworkContext, const char *url )
{
    int32_t returnStatus = EXIT_FAILURE;

    TlsTransportStatus_t tlsStatus;
    pNetworkContext->pcHostname = url;
    pNetworkContext->xPort = HTTPS_PORT;
    pNetworkContext->pxTls = NULL;
    pNetworkContext->xTlsContextSemaphore = xSemaphoreCreateMutexStatic(&xTlsContextSemaphoreBuffer);

    pNetworkContext->pcServerRootCA = root_cert_auth_start;
    pNetworkContext->pcServerRootCASize = root_cert_auth_end - root_cert_auth_start;
    pNetworkContext->disableSni = 1;

    if( HTTPS_PORT == 443 )
    {
        static const char * pcAlpnProtocols[] = { NULL, NULL };
        pcAlpnProtocols[0] = IOT_CORE_ALPN_PROTOCOL_NAME;
        pNetworkContext->pAlpnProtos = pcAlpnProtocols;

    } else {
        pNetworkContext->pAlpnProtos = NULL;
    }

    LogDebug( ( "Establishing a TLS session to %.*s:%d.", strlen( url ), url, HTTPS_PORT ) );

    tlsStatus = xTlsConnect ( pNetworkContext );

    if( tlsStatus == TLS_TRANSPORT_SUCCESS )
    {
        LogInfo( ( "OK OK OK connected to S3" ) );
        returnStatus = EXIT_SUCCESS;
    }
    else
    {
        LogError( ( "Failed to connect to HTTP server %s.", url ) );
        returnStatus = EXIT_FAILURE;
    }

    return returnStatus;
}

static int32_t connectToS3ForDownload( NetworkContext_t * pNetworkContext)
{
    return connectToS3(pNetworkContext, AWS_S3_ENDPOINT);
}

static int32_t connectToS3ForUpload( NetworkContext_t * pNetworkContext )
{
    const char * pAddress = NULL;
    int32_t returnStatus = EXIT_FAILURE;

    /* Retrieve the address location and length from S3_PRESIGNED_PUT_URL. */
    HTTPStatus_t httpStatus = getUrlAddress( s3Url,
                                strlen(s3Url),
                                &pAddress,
                                &serverHostLength );


    if(httpStatus != HTTPSuccess)
    {
        LogError(("Failed to get URL from Presigned URL\n"));
        return returnStatus;
    }
    memcpy( serverHost, pAddress, serverHostLength );
    serverHost[ serverHostLength ] = '\0';

    return connectToS3(pNetworkContext, serverHost);
}

static bool downloadS3ObjectFile( const TransportInterface_t * pTransportInterface,
                                  const char * pPath )
{
    bool returnStatus = false;
    HTTPStatus_t httpStatus = HTTPSuccess; 
    size_t numReqBytes = 0;

    SigV4Status_t sigv4Status = SigV4Success;
    SigV4HttpParameters_t sigv4HttpParams;

    char * pHeaders = NULL;
    size_t headersLen = 0;
    char * signature = NULL;
    size_t signatureLen = 0;

    assert( pPath != NULL );

    serverHostLength = strlen( AWS_S3_ENDPOINT );
    memcpy( serverHost, AWS_S3_ENDPOINT, serverHostLength );
    serverHost[ serverHostLength ] = '\0';

    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );

    requestInfo.pHost = serverHost;
    requestInfo.hostLen = serverHostLength;
    requestInfo.pMethod = HTTP_METHOD_GET;
    requestInfo.methodLen = HTTP_METHOD_GET_LENGTH;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );

    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;
    response.pBuffer = userBuffer;
    response.bufferLen = USER_BUFFER_LENGTH;
    returnStatus = getS3ObjectFileSize( &downloadFileSizeTotal,
                                        pTransportInterface,
                                        serverHost,
                                        serverHostLength,
                                        pPath );

    if( downloadFileSizeTotal < RANGE_REQUEST_LENGTH )
    {
        numReqBytes = downloadFileSizeTotal;
    }
    else
    {
        numReqBytes = RANGE_REQUEST_LENGTH;
    }

    while( !aws_s3_exit && ( returnStatus == true ) 
            && ( httpStatus == HTTPSuccess ) && ( downloadCurByteTracking < downloadFileSizeTotal ) )
    {
        httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                          &requestInfo );

        if( returnStatus == true )
        {
            httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                               ( const char * ) SIGV4_HTTP_X_AMZ_DATE_HEADER,
                                               ( size_t ) sizeof( SIGV4_HTTP_X_AMZ_DATE_HEADER ) - 1,
                                               ( const char * ) pDateISO8601,
                                               SIGV4_ISO_STRING_LEN );

            if( httpStatus != HTTPSuccess )
            {
                LogError( ( "Failed to add X-AMZ-DATE to request headers: Error=%s.",
                            HTTPClient_strerror( httpStatus ) ) );
                returnStatus = false;
            }
        }

        if( returnStatus == true )
        {
            /* S3 requires the security token as part of the canonical headers. */
            httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                               ( const char * ) SIGV4_HTTP_X_AMZ_SECURITY_TOKEN_HEADER,
                                               ( size_t ) ( sizeof( SIGV4_HTTP_X_AMZ_SECURITY_TOKEN_HEADER ) - 1 ),
                                               ( const char * ) pSecurityToken,
                                               ( size_t ) securityTokenLen );

            if( httpStatus != HTTPSuccess )
            {
                LogError( ( "Failed to add X-AMZ-SECURITY-TOKEN to request headers: Error=%s.",
                            HTTPClient_strerror( httpStatus ) ) );
                returnStatus = false;
            }
        }

        if( httpStatus == HTTPSuccess )
        {
            httpStatus = HTTPClient_AddRangeHeader( &requestHeaders,
                                                    downloadCurByteTracking,
                                                    downloadCurByteTracking + numReqBytes - 1 );
        }
        else
        {
            LogError( ( "Failed to add range header to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
        }

        /* Get the hash of the payload. */
        sha256( ( const char * ) S3_REQUEST_EMPTY_PAYLOAD, 0, pPayloadHashDigest );
        lowercaseHexEncode( ( const char * ) pPayloadHashDigest, SHA256_HASH_DIGEST_LENGTH, hexencoded );

        if( returnStatus == true )
        {
            httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                               ( const char * ) SIGV4_HTTP_X_AMZ_CONTENT_SHA256_HEADER,
                                               ( size_t ) ( sizeof( SIGV4_HTTP_X_AMZ_CONTENT_SHA256_HEADER ) - 1 ),
                                               ( const char * ) hexencoded,
                                               64 );

            if( httpStatus != HTTPSuccess )
            {
                LogError( ( "Failed to add X-AMZ-CONTENT-SHA256-HEADER to request headers: Error=%s.",
                            HTTPClient_strerror( httpStatus ) ) );
                returnStatus = false;
            }
        }

        /* Move request header pointer past the initial headers which are added by coreHTTP
         * library and are not required by SigV4 library. */
        getHeaderStartLocFromHttpRequest( requestHeaders, &pHeaders, &headersLen );

        /* Setup the HTTP parameters. */
        sigv4HttpParams.pHttpMethod = requestInfo.pMethod;
        sigv4HttpParams.httpMethodLen = requestInfo.methodLen;
        /* None of the requests parameters below are pre-canonicalized */
        sigv4HttpParams.flags = 0;
        sigv4HttpParams.pPath = requestInfo.pPath;
        sigv4HttpParams.pathLen = requestInfo.pathLen;
        /* AWS S3 request does not require any Query parameters. */
        sigv4HttpParams.pQuery = NULL;
        sigv4HttpParams.queryLen = 0;
        sigv4HttpParams.pHeaders = pHeaders;
        sigv4HttpParams.headersLen = headersLen;
        sigv4HttpParams.pPayload = S3_REQUEST_EMPTY_PAYLOAD;
        sigv4HttpParams.payloadLen = sizeof( S3_REQUEST_EMPTY_PAYLOAD ) - 1U;

        /* Initializing sigv4Params with Http parameters required for the HTTP request. */
        sigv4Params.pHttpParameters = &sigv4HttpParams;

        if( returnStatus == true )
        {
            /* Generate HTTP Authorization header using SigV4_GenerateHTTPAuthorization API. */
            sigv4Status = SigV4_GenerateHTTPAuthorization( &sigv4Params, pSigv4Auth, &sigv4AuthLen, &signature, &signatureLen );

            if( sigv4Status != SigV4Success )
            {
                LogError( ( "SigV4 Library Failed to generate AUTHORIZATION Header." ) );
                returnStatus = false;
            }
        }

        /* Add the authorization header to the HTTP request headers. */
        if( returnStatus == true )
        {
            httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                               ( const char * ) SIGV4_AUTH_HEADER_FIELD_NAME,
                                               ( size_t ) sizeof( SIGV4_AUTH_HEADER_FIELD_NAME ) - 1,
                                               ( const char * ) pSigv4Auth,
                                               ( size_t ) sigv4AuthLen );
            LogDebug( ( "Request Headers:\n%.*s",
                        ( int32_t ) requestHeaders.headersLen,
                        ( char * ) requestHeaders.pBuffer ) );
            if( httpStatus != HTTPSuccess )
            {
                LogError( ( "Failed to add AUTHORIZATION Header to request headers: Error=%s.",
                            HTTPClient_strerror( httpStatus ) ) );
                returnStatus = false;
            }
        }

        if( httpStatus == HTTPSuccess )
        {
            LogDebug( ( "Downloading bytes %d-%d, out of %d total bytes, from %s...:  ",
                       ( int32_t ) ( downloadCurByteTracking ),
                       ( int32_t ) ( downloadCurByteTracking + numReqBytes - 1 ),
                       ( int32_t ) downloadFileSizeTotal,
                       serverHost ) );
            LogDebug( ( "Request Headers:\n%.*s",
                        ( int32_t ) requestHeaders.headersLen,
                        ( char * ) requestHeaders.pBuffer ) );

            /* Send HTTP Get request to AWS S3 and receive response. */
            httpStatus = HTTPClient_Send( pTransportInterface,
                                          &requestHeaders,
                                          NULL,
                                          0,
                                          &response,
                                          0 );
        }
        else
        {
            LogError( ( "Failed to add Range header to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
        }

        if( httpStatus == HTTPSuccess && response.statusCode != 403)
        {
            LogDebug( ( "Response Headers:\n%.*s",
                        ( int32_t ) response.headersLen,
                        response.pHeaders ) );
            #if 0
            LogInfo( ( "Response Body:\n%.*s\n",
                       ( int32_t ) response.bodyLen,
                       response.pBody ) );
            #endif
            
            local_file_write(response.pBody, response.bodyLen);

            LogInfo( ( "Downloaded %.1f", ((float)downloadCurByteTracking * 100) / downloadFileSizeTotal ) );

            downloadCurByteTracking += response.contentLength;

            if( ( downloadFileSizeTotal - downloadCurByteTracking ) < numReqBytes )
            {
                numReqBytes = downloadFileSizeTotal - downloadCurByteTracking;
            }

            returnStatus = ( response.statusCode == HTTP_STATUS_CODE_PARTIAL_CONTENT ) ? true : false;
        }
        else
        {
            LogError( ( "An error occured in downloading the file. "
                        "Failed to send HTTP GET request to %s%s: Error=%s.",
                        serverHost, pPath, HTTPClient_strerror( httpStatus ) ) );
        }

        downloadResponseStatusCode = response.statusCode;

        if(downloadResponseStatusCode == 403)
        {
            break;
        }

        if( returnStatus != true )
        {
            
            LogError( ( "Error Response code = %u", downloadResponseStatusCode) );
        }
    }
    if(aws_s3_exit)
    {
        returnStatus = false;
    }
    return( ( returnStatus == true ) && ( httpStatus == HTTPSuccess ) );
}

/*-----------------------------------------------------------*/

static bool getS3ObjectFileSize( size_t * pFileSize,
                                 const TransportInterface_t * pTransportInterface,
                                 const char * pHost,
                                 size_t hostLen,
                                 const char * pPath )
{
    bool returnStatus = true;
    HTTPStatus_t httpStatus = HTTPSuccess;
    HTTPRequestHeaders_t requestHeaders;
    HTTPRequestInfo_t requestInfo;
    HTTPResponse_t response;

    char * pFileSizeStr = NULL;
    char * contentRangeValStr = NULL;
    size_t contentRangeValStrLength = 0;

    SigV4Status_t sigv4Status = SigV4Success;
    SigV4HttpParameters_t sigv4HttpParams;

    char * pHeaders = NULL;
    size_t headersLen = 0;

    char * signature = NULL;
    size_t signatureLen = 0;

    assert( pHost != NULL );
    assert( pPath != NULL );

    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );

    requestInfo.pHost = pHost;
    requestInfo.hostLen = hostLen;
    requestInfo.pMethod = HTTP_METHOD_GET;
    requestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );
    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;
    response.pBuffer = userBuffer;
    response.bufferLen = USER_BUFFER_LENGTH;

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      &requestInfo );

    if( httpStatus != HTTPSuccess )
    {
        LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                    HTTPClient_strerror( httpStatus ) ) );
        returnStatus = false;
    }

    /* Get the hash of the payload. */
    sha256( ( const char * ) S3_REQUEST_EMPTY_PAYLOAD, 0, pPayloadHashDigest );
    lowercaseHexEncode( ( const char * ) pPayloadHashDigest, SHA256_HASH_DIGEST_LENGTH, hexencoded );

    if( returnStatus == true )
    {
        /* Add the sigv4 required headers to the request. */
        httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                           ( const char * ) SIGV4_HTTP_X_AMZ_DATE_HEADER,
                                           ( size_t ) sizeof( SIGV4_HTTP_X_AMZ_DATE_HEADER ) - 1,
                                           ( const char * ) pDateISO8601,
                                           SIGV4_ISO_STRING_LEN );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add X-AMZ-DATE to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* S3 requires the security token as part of the canonical headers. IoT for example
         * does not; it is added as part of the path. */
        httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                           ( const char * ) SIGV4_HTTP_X_AMZ_SECURITY_TOKEN_HEADER,
                                           ( size_t ) ( sizeof( SIGV4_HTTP_X_AMZ_SECURITY_TOKEN_HEADER ) - 1 ),
                                           ( const char * ) pSecurityToken,
                                           ( size_t ) securityTokenLen );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add X-AMZ-SECURITY-TOKEN to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Add the header to get bytes=0-0. S3 will respond with a Content-Range
         * header that contains the size of the file in it. This header will
         * look like: "Content-Range: bytes 0-0/FILESIZE". The body will have a
         * single byte that we are ignoring. */
        httpStatus = HTTPClient_AddRangeHeader( &requestHeaders, 0, 0 );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add Range header to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                           ( const char * ) SIGV4_HTTP_X_AMZ_CONTENT_SHA256_HEADER,
                                           ( size_t ) ( sizeof( SIGV4_HTTP_X_AMZ_CONTENT_SHA256_HEADER ) - 1 ),
                                           ( const char * ) hexencoded,
                                           64 );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to add X-AMZ-CONTENT-SHA256-HEADER to request headers: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    /* Move request header pointer past the initial headers which are added by coreHTTP
     * library and are not required by SigV4 library. */
    getHeaderStartLocFromHttpRequest( requestHeaders, &pHeaders, &headersLen );

    /* Setup the HTTP parameters. */
    sigv4HttpParams.pHttpMethod = requestInfo.pMethod;
    sigv4HttpParams.httpMethodLen = requestInfo.methodLen;
    /* None of the requests parameters below are pre-canonicalized */
    sigv4HttpParams.flags = 0;
    sigv4HttpParams.pPath = requestInfo.pPath;
    sigv4HttpParams.pathLen = requestInfo.pathLen;
    /* AWS S3 request does not require any Query parameters. */
    sigv4HttpParams.pQuery = NULL;
    sigv4HttpParams.queryLen = 0;
    sigv4HttpParams.pHeaders = pHeaders;
    sigv4HttpParams.headersLen = headersLen;
    sigv4HttpParams.pPayload = S3_REQUEST_EMPTY_PAYLOAD;
    sigv4HttpParams.payloadLen = strlen( S3_REQUEST_EMPTY_PAYLOAD );

    /* Initializing sigv4Params with Http parameters required for the HTTP request. */
    sigv4Params.pHttpParameters = &sigv4HttpParams;

    if( returnStatus == true )
    {
        /* Generate HTTP Authorization header using SigV4_GenerateHTTPAuthorization API. */
        sigv4Status = SigV4_GenerateHTTPAuthorization( &sigv4Params, pSigv4Auth, &sigv4AuthLen, &signature, &signatureLen );

        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Failed to generate HTTP AUTHORIZATION Header. " ) );
            returnStatus = false;
        }
    }

    /* Add the authorization header to the HTTP request headers. */
    if( returnStatus == true )
    {
        httpStatus = HTTPClient_AddHeader( &requestHeaders,
                                           ( const char * ) SIGV4_AUTH_HEADER_FIELD_NAME,
                                           ( size_t ) sizeof( SIGV4_AUTH_HEADER_FIELD_NAME ) - 1,
                                           ( const char * ) pSigv4Auth,
                                           ( size_t ) sigv4AuthLen );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to send HTTP GET request to %s%s: Error=%s.",
                        pHost, pPath, HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        /* Send HTTP Get request to AWS S3 to get the file size. */
        httpStatus = HTTPClient_Send( pTransportInterface,
                                      &requestHeaders,
                                      NULL,
                                      0,
                                      &response,
                                      0 );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to send HTTP GET request to %s%s: Error=%s.",
                        pHost, pPath, HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        LogDebug( ( "Received HTTP response from %s%s...",
                    pHost, pPath ) );
        LogDebug( ( "Response Headers:\n%.*s",
                    ( int32_t ) response.headersLen,
                    response.pHeaders ) );
        LogDebug( ( "Response Body:\n%.*s\n",
                    ( int32_t ) response.bodyLen,
                    response.pBody ) );

        if( response.statusCode != HTTP_STATUS_CODE_PARTIAL_CONTENT )
        {
            LogError( ( "Received an invalid response from the server "
                        "(Status Code: %u).",
                        response.statusCode ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        LogInfo( ( "Received successful response from server "
                   "(Status Code: %u).",
                   response.statusCode ) );

        httpStatus = HTTPClient_ReadHeader( &response,
                                            ( char * ) HTTP_CONTENT_RANGE_HEADER_FIELD,
                                            ( size_t ) HTTP_CONTENT_RANGE_HEADER_FIELD_LENGTH,
                                            ( const char ** ) &contentRangeValStr,
                                            &contentRangeValStrLength );

        if( httpStatus != HTTPSuccess )
        {
            LogError( ( "Failed to read Content-Range header from HTTP response: Error=%s.",
                        HTTPClient_strerror( httpStatus ) ) );
            returnStatus = false;
        }
    }

    /* Parse the Content-Range header value to get the file size. */
    if( returnStatus == true )
    {
        pFileSizeStr = strstr( contentRangeValStr, "/" );

        if( pFileSizeStr == NULL )
        {
            LogError( ( "'/' not present in Content-Range header value: %s.",
                        contentRangeValStr ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        pFileSizeStr += sizeof( char );
        *pFileSize = ( size_t ) strtoul( pFileSizeStr, NULL, 10 );

        if( ( *pFileSize == 0 ) || ( *pFileSize == UINT32_MAX ) )
        {
            LogError( ( "Error using strtoul to get the file size from %s: fileSize=%d.",
                        pFileSizeStr, ( int32_t ) *pFileSize ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        LogInfo( ( "The file is %d bytes long.", ( int32_t ) *pFileSize ) );
    }

    return returnStatus;
}

static bool check_valid_s3_object_name(const char * s3ObjectName)
{
    if(s3ObjectName != NULL && s3ObjectName[0] == '/')
    {
        return true;
    }
    return false;
}

int aws_s3_download( const char * s3ObjectName, const char * saveFile)
{
    int noRetriesCount = 0;
    bool ret = false, credentialStatus = false;
    int32_t returnStatus = EXIT_FAILURE;
    TransportInterface_t transportInterface;
    NetworkContext_t networkContext = {0};

    cleanEnv();

    int64_t t1 = esp_timer_get_time();

    ret = check_valid_s3_object_name(s3ObjectName);

    if(ret)
    {
        local_file_init(saveFile, true);
        do
        {
            returnStatus = connectToServerWithBackoffRetries( connectToIotServer,
                                                                &networkContext );

            if( returnStatus == EXIT_FAILURE )
            {
                LogError(("Failed to connect to IoT server"));
            }
            else if( returnStatus == EXIT_SUCCESS )
            {
                LogInfo( ( "OK OK OK OK to connect to IoT server" ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
                transportInterface.recv = espTlsTransportRecv;
                transportInterface.send = espTlsTransportSend;
                transportInterface.pNetworkContext = &networkContext;
                transportInterface.writev = NULL;
            }

            credentialResponse.pBuffer = pAwsIotHttpBuffer;
            credentialResponse.bufferLen = CREDENTIAL_BUFFER_LENGTH;

            credentialStatus = getTemporaryCredentials( &transportInterface, pDateISO8601, sizeof( pDateISO8601 ), &credentialResponse, &sigvCreds );

            returnStatus = ( credentialStatus == true ) ? EXIT_SUCCESS : EXIT_FAILURE;

            if( returnStatus == EXIT_FAILURE )
            {
                LogError( ( "Failed to get temporary credentials from AWS IoT CREDENTIALS PROVIDER" ) );
            }
            else
            {
                LogInfo( ( "OK OK OK to get temporary credentials from AWS IoT CREDENTIALS PROVIDER" ) );
            }

            ( void ) xTlsDisconnect( &networkContext );

            if( returnStatus == EXIT_SUCCESS )
            {

                returnStatus = connectToServerWithBackoffRetries( connectToS3ForDownload,
                                                                    &networkContext );

                if( returnStatus == EXIT_FAILURE )
                {
                    LogError( ( "Failed to connect to AWS S3 HTTP server" ) );
                }
                if( returnStatus == EXIT_SUCCESS )
                {
                    ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
                    transportInterface.recv = espTlsTransportRecv;
                    transportInterface.send = espTlsTransportSend;
                    transportInterface.pNetworkContext = &networkContext;
                    transportInterface.writev = NULL;
                }

                pPath = s3ObjectName;

                if( returnStatus == EXIT_SUCCESS )
                {
                    
                    ret = downloadS3ObjectFile( &transportInterface,
                                                pPath );

                    returnStatus = ( ret == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
                }
                ( void ) xTlsDisconnect( &networkContext );
            }

            noRetriesCount++;

            if( returnStatus == EXIT_SUCCESS )
            {
                LogInfo( ( "Downloading %d is successful.", noRetriesCount ) );
            }
            else if( noRetriesCount < DOWNLOAD_MAX_RETRIES_LOOP_COUNT )
            {
                LogWarn( ( "Retry No %d failed. Retrying...", noRetriesCount ) );
                sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S );
            }
            else
            {
                LogError( ( "All %d retries failed.", DOWNLOAD_MAX_RETRIES_LOOP_COUNT ) );
                break;
            }
        
        } while (!aws_s3_exit && returnStatus != EXIT_SUCCESS);
    }
    local_file_close();
    int64_t t2 = esp_timer_get_time();
    LogInfo(("Total time: %lld ms", (t2 - t1)/1000));
    
    return returnStatus;
}

static bool generateS3ObjectFilePresignedURL( const char * pHost,
                                           size_t hostLen,
                                           const char * pPath,
                                           bool is_put )
{
    bool returnStatus = true;
    HTTPStatus_t httpStatus = HTTPSuccess;
    HTTPRequestHeaders_t requestHeaders;
    HTTPRequestInfo_t requestInfo;
    HTTPResponse_t response;

    SigV4Status_t sigv4Status = SigV4Success;
    SigV4HttpParameters_t sigv4HttpParams;

    char * pHeaders = NULL;
    size_t headersLen = 0;

    /* Store Signature used in AWS HTTP requests generated using SigV4 library. */
    char * signature = NULL;
    size_t signatureLen = 0;

    assert( pHost != NULL );
    assert( pPath != NULL );

    /* Initialize all HTTP Client library API structs to 0. */
    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );
    ( void ) memset( s3Url, 0, AWS_S3_URL_LENGTH );

    strcat(s3Url, "https://");
    strcat(s3Url, AWS_S3_ENDPOINT);
    strcat(s3Url, pPath);
    strcat(s3Url, "?");
    
    LogInfo(( "the S3 URL = %s", s3Url ));

    /* Initialize the request object. */
    requestInfo.pHost = pHost;
    requestInfo.hostLen = hostLen;
    if(is_put)
    {
        requestInfo.pMethod = HTTP_METHOD_PUT;
        requestInfo.methodLen = sizeof( HTTP_METHOD_PUT ) - 1;
    }
    else
    {
        requestInfo.pMethod = HTTP_METHOD_GET;
        requestInfo.methodLen = sizeof( HTTP_METHOD_GET ) - 1;
    }
    
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );
    requestInfo.reqFlags = HTTP_REQUEST_NO_USER_AGENT_FLAG;
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;
    response.pBuffer = userBuffer;
    response.bufferLen = USER_BUFFER_LENGTH;

    LogInfo( ( "Getting presigned URL..." ) );

    httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                      &requestInfo );

    if( httpStatus != HTTPSuccess )
    {
        LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                    HTTPClient_strerror( httpStatus ) ) );
        returnStatus = false;
    }

    /* Move request header pointer past the initial headers which are added by coreHTTP
     * library and are not required by SigV4 library. */
    getHeaderStartLocFromHttpRequest( requestHeaders, &pHeaders, &headersLen );

    int dateOffset = ( sigvCreds.accessKeyIdLen + 1 );
    /* <your-access-key-id>/<date>/<AWS Region>/<AWS-service>/aws4_request */
    char x_amz_credentials[ 256 ] = { 0 };
    strncat( x_amz_credentials, sigvCreds.pAccessKeyId, sigvCreds.accessKeyIdLen );
    strcat( x_amz_credentials, "/" );
    memcpy( x_amz_credentials + dateOffset, pDateISO8601, 8 );
    strcat( x_amz_credentials, "/" );
    strcat( x_amz_credentials, AWS_S3_BUCKET_REGION );
    strcat( x_amz_credentials, "/s3/aws4_request" );

    /* https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html */
    char canonical_queries[ 2048 ] = "";
    memset(canonical_queries, 0, 2048);
    strcat( canonical_queries, "X-Amz-Algorithm=" );
    strcat( canonical_queries, SIGV4_AWS4_HMAC_SHA256 );
    strcat( canonical_queries, "&X-Amz-Credential=" );
    strcat( canonical_queries, x_amz_credentials );
    strcat( canonical_queries, "&X-Amz-Date=" );
    strncat( canonical_queries, pDateISO8601, SIGV4_ISO_STRING_LEN );
    strcat( canonical_queries, "&X-Amz-Expires=3600" );
    strcat( canonical_queries, "&X-Amz-Security-Token=" );
    strncat( canonical_queries, pSecurityToken, securityTokenLen );
    strcat( canonical_queries, "&X-Amz-SignedHeaders=host" );

    /* Setup the HTTP parameters. */
    sigv4HttpParams.pHttpMethod = requestInfo.pMethod;
    sigv4HttpParams.httpMethodLen = requestInfo.methodLen;
    /* None of the requests parameters below are pre-canonicalized */
    sigv4HttpParams.flags = SIGV4_HTTP_IS_PRESIGNED_URL;
    sigv4HttpParams.pPath = requestInfo.pPath;
    sigv4HttpParams.pathLen = requestInfo.pathLen;
    sigv4HttpParams.pQuery = canonical_queries;
    sigv4HttpParams.queryLen = strlen( canonical_queries );
    sigv4HttpParams.pHeaders = pHeaders;
    sigv4HttpParams.headersLen = headersLen;
    sigv4HttpParams.pPayload = S3_REQUEST_EMPTY_PAYLOAD;
    sigv4HttpParams.payloadLen = strlen( S3_REQUEST_EMPTY_PAYLOAD );

    /* Initializing sigv4Params with Http parameters required for the HTTP request. */
    sigv4Params.pHttpParameters = &sigv4HttpParams;

    if( returnStatus == true )
    {
        /* Generate HTTP Authorization header using SigV4_GenerateHTTPAuthorization API. */
        sigv4Status = SigV4_GenerateHTTPAuthorization( &sigv4Params, pSigv4Auth, &sigv4AuthLen, &signature, &signatureLen );

        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Failed to generate HTTP AUTHORIZATION Header. " ) );
            returnStatus = false;
        }
    }

    if( returnStatus == true )
    {
        strcat( s3Url, "X-Amz-Algorithm=" );
        strcat( s3Url, SIGV4_AWS4_HMAC_SHA256 );
        strcat( s3Url, "&X-Amz-Credential=" );
        size_t encodedLen = sizeof( s3Url ) - strlen( s3Url );
        sigv4Status = SigV4_EncodeURI( x_amz_credentials,
                                       strlen( x_amz_credentials ),
                                       s3Url + strlen( s3Url ),
                                       &encodedLen,
                                       true /* encode slash */,
                                       false /* do not double encode equal */ );

        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Failed to run SigV4_EncodeURI on '%s'.", x_amz_credentials ) );
            returnStatus = false;
        }

        strcat( s3Url, "&X-Amz-Date=" );
        strncat( s3Url, pDateISO8601, SIGV4_ISO_STRING_LEN );
        strcat( s3Url, "&X-Amz-Expires=3600" );
        strcat( s3Url, "&X-Amz-SignedHeaders=host" );
        strcat( s3Url, "&X-Amz-Security-Token=" );
        encodedLen = sizeof( s3Url ) - strlen( s3Url );
        sigv4Status = SigV4_EncodeURI( pSecurityToken,
                                       securityTokenLen,
                                       s3Url + strlen( s3Url ),
                                       &encodedLen,
                                       true /* encode slash */,
                                       false /* do not double encode equal */ );

        if( sigv4Status != SigV4Success )
        {
            LogError( ( "Failed to run SigV4_EncodeURI on '%s'.", pSecurityToken ) );
            returnStatus = false;
        }

        strcat( s3Url, "&X-Amz-Signature=" );
        strncat( s3Url, signature, signatureLen );
        if(is_put)
        {
            LogInfo( ( "presigned_url for PUT = \n%s", s3Url ) );
        }
        else
        {
            LogInfo( ( "presigned_url for GET = \n%s", s3Url ) );
        }
    }

    return returnStatus;
}

const char *get_aws_s3_presigned_url( void )
{
    return s3Url;
}

int aws_s3_gen_presigned_url( const char *s3ObjectName, bool is_put)
{
    bool ret = false, credentialStatus = false;
    int32_t returnStatus = EXIT_FAILURE;
    TransportInterface_t transportInterface;
    NetworkContext_t networkContext = {0};  

    ret = check_valid_s3_object_name(s3ObjectName);

    if(ret)
    {
        returnStatus = connectToServerWithBackoffRetries( connectToIotServer,
                                                            &networkContext );

        if( returnStatus == EXIT_FAILURE )
        {
            LogError(("Failed to connect to IoT server"));
        }
        else if( returnStatus == EXIT_SUCCESS )
        {
            LogInfo( ( "OK OK OK OK to connect to IoT server" ) );
        }

        if( returnStatus == EXIT_SUCCESS )
        {
            ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
            transportInterface.recv = espTlsTransportRecv;
            transportInterface.send = espTlsTransportSend;
            transportInterface.pNetworkContext = &networkContext;
            transportInterface.writev = NULL;
        }

        credentialResponse.pBuffer = pAwsIotHttpBuffer;
        credentialResponse.bufferLen = CREDENTIAL_BUFFER_LENGTH;

        credentialStatus = getTemporaryCredentials( &transportInterface, pDateISO8601, sizeof( pDateISO8601 ), &credentialResponse, &sigvCreds );

        returnStatus = ( credentialStatus == true ) ? EXIT_SUCCESS : EXIT_FAILURE;

        if( returnStatus == EXIT_FAILURE )
        {
            LogError( ( "Failed to get temporary credentials from AWS IoT CREDENTIALS PROVIDER %s.",
                        serverHost ) );
        }
        else
        {
            LogInfo( ( "OK OK OK to get temporary credentials from AWS IoT CREDENTIALS PROVIDER %s.",
                        serverHost ) );
        }

        ( void ) xTlsDisconnect( &networkContext );

        if( returnStatus == EXIT_SUCCESS )
        {
            serverHostLength = strlen( AWS_S3_ENDPOINT );
            memcpy( serverHost, AWS_S3_ENDPOINT, serverHostLength );
            serverHost[ serverHostLength ] = '\0';

            if( returnStatus == EXIT_SUCCESS )
            {
                ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
                transportInterface.recv = espTlsTransportRecv;
                transportInterface.send = espTlsTransportSend;
                transportInterface.pNetworkContext = &networkContext;
                transportInterface.writev = NULL;
            }

            pPath = s3ObjectName;

            if(is_put)
            {
                if( returnStatus == EXIT_SUCCESS )
                {
                    ret = generateS3ObjectFilePresignedURL( serverHost,
                                                        serverHostLength,
                                                        pPath, true);

                    returnStatus = ( ret == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
                }
            }
            else
            {
                if( returnStatus == EXIT_SUCCESS )
                {
                    ret = generateS3ObjectFilePresignedURL( serverHost,
                                                        serverHostLength,
                                                        pPath, false);

                    returnStatus = ( ret == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
                }
            }
        }
    }

    return returnStatus;
}

static bool uploadS3ObjectFile( const TransportInterface_t * pTransportInterface,
                                const char * pPath )
{
    bool returnStatus = false;
    HTTPStatus_t httpStatus = HTTPSuccess;

    assert( pPath != NULL );

    ( void ) memset( &requestHeaders, 0, sizeof( requestHeaders ) );
    ( void ) memset( &requestInfo, 0, sizeof( requestInfo ) );
    ( void ) memset( &response, 0, sizeof( response ) );

    requestInfo.pHost = serverHost;
    requestInfo.hostLen = serverHostLength;
    requestInfo.pMethod = HTTP_METHOD_PUT;
    requestInfo.methodLen = HTTP_METHOD_PUT_LENGTH;
    requestInfo.pPath = pPath;
    requestInfo.pathLen = strlen( pPath );

    requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;
    requestHeaders.pBuffer = userBuffer;
    requestHeaders.bufferLen = USER_BUFFER_LENGTH;
    response.pBuffer = userBuffer;
    response.bufferLen = USER_BUFFER_LENGTH;

    if( httpStatus == HTTPSuccess )
    {
        httpStatus = HTTPClient_InitializeRequestHeaders( &requestHeaders,
                                                        &requestInfo );
    }

    if( httpStatus == HTTPSuccess )
    {
        LogInfo( ( "Request Headers:\n%.*s",
                    ( int32_t ) requestHeaders.headersLen,
                    ( char * ) requestHeaders.pBuffer ) );
                    
        uint8_t *data;
        int len;
        local_file_read(&data, &len);
        LogInfo(("Fize size to upload %d", len));
        httpStatus = HTTPClient_Send( pTransportInterface,
                            &requestHeaders,
                            ( const uint8_t * ) data,
                            len,
                            &response,
                            0 );  
        free(data);
                                
    }
    else
    {
        LogError( ( "Failed to initialize HTTP request headers: Error=%s.",
                    HTTPClient_strerror( httpStatus ) ) );
    }

    if( httpStatus == HTTPSuccess )
    {
        LogDebug( ( "Received HTTP response from %s%s...",
                    serverHost, pPath ) );
        LogDebug( ( "Response Headers:\n%.*s",
                    ( int32_t ) response.headersLen,
                    response.pHeaders ) );
        LogDebug( ( "Response Body:\n%.*s\n",
                    ( int32_t ) response.bodyLen,
                    response.pBody ) );

        returnStatus = ( response.statusCode == 200 ) ? true : false;
    }
    else
    {
        LogError( ( "Response Body:\n%.*s\n",
                    ( int32_t ) response.bodyLen,
                    response.pBody ) );
        LogError( ( "An error occurred in uploading the file."
                    "Failed to send HTTP PUT request to %s%s: Error=%s.",
                    serverHost, pPath, HTTPClient_strerror( httpStatus ) ) );
    }

    if( returnStatus == true )
    {
        LogDebug( ( "Received successful response from server "
                "(Status Code: %u).",
                response.statusCode ) );
    }
    else
    {
        LogError( ( "Received an invalid response from the server "
                    "(Status Code: %u).",
                    response.statusCode ) );
    }

    return( ( returnStatus == true ) && ( httpStatus == HTTPSuccess ) );
}

int aws_s3_upload( const char * s3ObjectName, const char * saveFile )
{
    int noRetriesCount = 0;
    HTTPStatus_t httpStatus = HTTPSuccess;
    size_t pathLen = 0;
    bool ret = false;
    int32_t returnStatus = EXIT_FAILURE;
    TransportInterface_t transportInterface;
    NetworkContext_t networkContext = {0};

    cleanEnv();

    returnStatus = aws_s3_gen_presigned_url(s3ObjectName, true);

    if( returnStatus == EXIT_SUCCESS )
    {
        LogInfo( ( "Done generate presigned_url" ) );
        LogInfo( ( "Start S3 uploading" ) );

        local_file_init(saveFile, false);

        do
        {
            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = connectToServerWithBackoffRetries( connectToS3ForUpload,
                                                            &networkContext );
            }

            if( returnStatus == EXIT_FAILURE )
            {
                LogError( ( "Failed to connect to HTTP server") );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                ( void ) memset( &transportInterface, 0, sizeof( transportInterface ) );
                transportInterface.recv = espTlsTransportRecv;
                transportInterface.send = espTlsTransportSend;
                transportInterface.pNetworkContext = &networkContext;
                transportInterface.writev = NULL;
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                httpStatus = getUrlPath( s3Url,
                                        strlen(s3Url),
                                        &pPath,
                                        &pathLen );

                returnStatus = ( httpStatus == HTTPSuccess ) ? EXIT_SUCCESS : EXIT_FAILURE;
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                ret = uploadS3ObjectFile( &transportInterface,
                                        pPath );
                returnStatus = ( ret == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
            }

            ( void ) xTlsDisconnect( &networkContext );

            noRetriesCount++;

            if( returnStatus == EXIT_SUCCESS )
            {
                LogInfo( ( "Uploading %d is successful.", noRetriesCount ) );
            }
            else if( noRetriesCount < UPLOAD_MAX_RETRIES_LOOP_COUNT )
            {
                LogWarn( ( "Retry No %d failed. Retrying...", noRetriesCount ) );
                sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S );
            }
            else
            {
                LogError( ( "All %d retries failed.", UPLOAD_MAX_RETRIES_LOOP_COUNT ) );
                break;
            }
        } while( !aws_s3_exit && returnStatus != EXIT_SUCCESS );
    }

    local_file_close();
    return returnStatus;
}
