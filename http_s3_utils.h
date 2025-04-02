#ifndef _HTTP_S3_UTILS_H_
#define _HTTP_S3_UTILS_H_

#include <stdlib.h>
#include <stdbool.h>
#include "transport_interface.h"
#include "core_http_client.h"

/**
 * @brief Length in bytes of hex encoded hash digest.
 */
#define HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH         ( ( ( uint16_t ) 64 ) )

/**
 * @brief Length in bytes of SHA256 hash digest.
 */
#define SHA256_HASH_DIGEST_LENGTH                     ( HEX_ENCODED_SHA256_HASH_DIGEST_LENGTH / 2 )

/**
 * @brief Function pointer for establishing connection to a server.
 *
 * @param[out] pNetworkContext Implementation-defined network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
typedef int32_t ( * TransportConnect_t )( NetworkContext_t * pNetworkContext );

/**
 * @brief Connect to a server with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[in] connectFunction Function pointer for establishing connection to a server.
 * @param[out] pNetworkContext Implementation-defined network context.
 *
 * @return EXIT_FAILURE on failure; EXIT_SUCCESS on successful connection.
 */
int32_t connectToServerWithBackoffRetries( TransportConnect_t connectFunction,
                                           NetworkContext_t * pNetworkContext );

/**
 * @brief Retrieve the path from the input URL.
 *
 * This function retrieves the location and length of the path from within the
 * input the URL. The query is not included in the length returned.
 *
 * The URL MUST start with "http://" or "https://" to find the path.
 *
 * For example, if pUrl is:
 * "https://www.somewebsite.com/path/to/item.txt?optionalquery=stuff"
 *
 * Then pPath and pPathLen will be the following:
 * *pPath = "/path/to/item.txt?optionalquery=stuff"
 * *pPathLen = 17
 *
 * @param[in] pUrl URL string to parse.
 * @param[in] urlLen The length of the URL string input.
 * @param[out] pPath pointer within input url that the path starts at.
 * @param[out] pPathLen Length of the path.
 *
 * @return The status of the parsing attempt:
 * HTTPSuccess if the path was successfully parsed,
 * HTTPParserInternalError if there was an error parsing the URL,
 * or HTTPNoResponse if the path was not found.
 */
HTTPStatus_t getUrlPath( const char * pUrl,
                         size_t urlLen,
                         const char ** pPath,
                         size_t * pPathLen );

/**
 * @brief Retrieve the Address from the input URL.
 *
 * This function retrieves the location and length of the address from within
 * the input URL. The path and query are not included in the length returned.
 *
 * The URL MUST start with "http://" or "https://" to find the address.
 *
 * For example, if pUrl is:
 * "https://www.somewebsite.com/path/to/item.txt?optionalquery=stuff"
 *
 * Then pAddress and pAddressLen will be the following:
 * *pAddress = "www.somewebsite.com/path/to/item.txt?optionalquery=stuff"
 * *pAddressLen = 19
 *
 * @param[in] pUrl URL string to parse.
 * @param[in] urlLen The length of the URL string input.
 * @param[out] pAddress pointer within input url that the address starts at.
 * @param[out] pAddressLen Length of the address.
 *
 * @return The status of the parsing attempt:
 * HTTPSuccess if the path was successfully parsed,
 * HTTPParserInternalError if there was an error parsing the URL,
 * or HTTPNoResponse if the path was not found.
 */
HTTPStatus_t getUrlAddress( const char * pUrl,
                            size_t urlLen,
                            const char ** pAddress,
                            size_t * pAddressLen );


/**
 * @brief Hex digest of provided string parameter.
 *
 * @param[in] pInputStr Input String to encode.
 * @param[in] inputStrLen Length of Input String to encode.
 * @param[out] pHexOutput Hex representation of @p pInputStr.
 */

void lowercaseHexEncode( const char * pInputStr,
                                size_t inputStrLen,
                                char * pHexOutput );

/*-----------------------------------------------------------*/
/**
 * @brief Calculate SHA256 digest.
 *
 * @param[in] pInput Input string to hash.
 * @param[in] ilen Length of input string.
 * @param[out] pOutput Buffer to store the generated hash.
 */

int32_t sha256( const char * pInput,
                       size_t ilen,
                       char * pOutput );

/**
 * @brief Application-defined Hash Initialization function provided
 * to the SigV4 library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this function.
 */

int32_t sha256Init( void * hashContext );

/**
 * @brief Application-defined Hash Update function provided to the SigV4 library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this function.
 */

int32_t sha256Update( void * hashContext,
                             const uint8_t * pInput,
                             size_t inputLen );

/**
 * @brief Application-defined Hash Final function provided to the SigV4 library.
 *
 * @note Refer to SigV4CryptoInterface_t interface documentation for this function.
 */

int32_t sha256Final( void * hashContext,
                            uint8_t * pOutput,
                            size_t outputLen );


#endif