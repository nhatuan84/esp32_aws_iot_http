#ifndef _HTTP_S3_UD_H_
#define _HTTP_S3_UD_H_

const char *get_aws_s3_presigned_url( void );
int aws_s3_gen_presigned_url( const char *s3ObjectName, bool is_put);
int aws_s3_upload( const char * s3ObjectName, const char * saveFile );
int aws_s3_download( const char * s3ObjectName, const char * saveFile ) ;
void aws_s3_ops_exit(void);

#endif