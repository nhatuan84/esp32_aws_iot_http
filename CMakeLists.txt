include( ${CMAKE_CURRENT_LIST_DIR}/sigv4-for-aws-iot-embedded-sdk/sigv4FilePaths.cmake )
include( ${CMAKE_CURRENT_LIST_DIR}/libraries/backoffAlgorithm/backoffAlgorithm/backoffAlgorithmFilePaths.cmake )
include( ${CMAKE_CURRENT_LIST_DIR}/libraries/coreHTTP/coreHTTP/httpFilePaths.cmake )
include( ${CMAKE_CURRENT_LIST_DIR}/libraries/coreJSON/coreJSON/jsonFilePaths.cmake )

set(COMPONENT_SRCS
	"${BACKOFF_ALGORITHM_SOURCES}"
    "${JSON_SOURCES}"
    "${HTTP_SOURCES}"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/coreHTTP/port/network_transport/network_transport.c"
    "${SIGV4_SOURCES}"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/common/posix_compat/semaphore.c"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/common/posix_compat/clock_esp.c"
	"http_s3_utils.c"
	"http_s3_ud.c"
)

set(COMPONENT_ADD_INCLUDEDIRS
    "."
    "${CMAKE_CURRENT_LIST_DIR}"
    "${SIGV4_INCLUDE_PUBLIC_DIRS}"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/common/logging"
    "${HTTP_INCLUDE_PUBLIC_DIRS}"
    "${JSON_INCLUDE_PUBLIC_DIRS}"
    "${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS}"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/coreHTTP/port/network_transport"
    "${CMAKE_CURRENT_LIST_DIR}/libraries/common/posix_compat"
)

idf_component_register(

    REQUIRES esp-tls mbedtls esp_timer nghttp common srvc_mqtt json
    SRCS "${COMPONENT_SRCS}"
    INCLUDE_DIRS ${COMPONENT_ADD_INCLUDEDIRS}
    EMBED_TXTFILES
        "${CMAKE_CURRENT_LIST_DIR}/certs/root_cert_auth.pem"
        "${CMAKE_CURRENT_LIST_DIR}/certs/client.crt"
        "${CMAKE_CURRENT_LIST_DIR}/certs/client.key"
        "${CMAKE_CURRENT_LIST_DIR}/certs/cert_aws_s3.pem"
)


                      