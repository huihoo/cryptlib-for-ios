/****************************************************************************
*																			*
*						 cryptlib SCEP Client Management					*
*						Copyright Peter Gutmann 1999-2008					*
*																			*
****************************************************************************/

#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "session.h"
  #include "scep.h"
#else
  #include "crypt.h"
  #include "enc_dec/asn1.h"
  #include "session/session.h"
  #include "session/scep.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in pnppki.c */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
int pnpPkiSession( INOUT SESSION_INFO *sessionInfoPtr );

#ifdef USE_SCEP

/****************************************************************************
*																			*
*					Additional Request Management Functions					*
*																			*
****************************************************************************/

/* Process one of the bolted-on additions to the basic SCEP protocol */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createAdditionalScepRequest( INOUT SESSION_INFO *sessionInfoPtr )
	{
	MESSAGE_CREATEOBJECT_INFO createInfo;
	HTTP_DATA_INFO httpDataInfo;
	HTTP_URI_INFO httpReqInfo;
	int length, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	
	REQUIRES( sessionInfoPtr->iAuthInContext == CRYPT_ERROR );

	/* Perform an HTTP GET with arguments "operation=GetCACert&message=*" */
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_GET );
	initHttpDataInfoEx( &httpDataInfo, sessionInfoPtr->receiveBuffer,
						sessionInfoPtr->receiveBufSize, &httpReqInfo );
	memcpy( httpReqInfo.attribute, "operation", 9 );
	httpReqInfo.attributeLen = 9;
	memcpy( httpReqInfo.value, "GetCACert", 9 );
	httpReqInfo.valueLen = 9;
	memcpy( httpReqInfo.extraData, "message=*", 9 );
	httpReqInfo.extraDataLen = 9;
	status = sread( &sessionInfoPtr->stream, &httpDataInfo,
					sizeof( HTTP_DATA_INFO ) );
	sioctlSet( &sessionInfoPtr->stream, STREAM_IOCTL_HTTPREQTYPES, 
			   STREAM_HTTPREQTYPE_POST );
	if( cryptStatusError( status ) )
		return( status );
	length = httpDataInfo.bytesAvail;

	/* Since we can't use readPkiDatagram() because of the weird dual-
	   purpose HTTP transport used in SCEP we have to duplicate portions of 
	   readPkiDatagram() here.  See the readPkiDatagram() function for code 
	   comments explaining the following operations */
	if( length < 4 || length >= MAX_INTLENGTH )
		{
		retExt( CRYPT_ERROR_UNDERFLOW,
				( CRYPT_ERROR_UNDERFLOW, SESSION_ERRINFO, 
				  "Invalid PKI message length %d", length ) );
		}
	status = length = \
		checkObjectEncoding( sessionInfoPtr->receiveBuffer, length );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid PKI message encoding" ) );
		}

	/* Import the CA certificate and save it for later use */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, length,
								CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		retExt( length, 
				( length, SESSION_ERRINFO, 
				  "Invalid SCEP CA certificate" ) );
		}
	sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;

	/* Process the server's key fingerprint */
	status = processKeyFingerprint( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure that the CA certificate meets the SCEP protocol 
	   requirements */
	if( !checkCACert( sessionInfoPtr->iAuthInContext ) )
		{
		retExt( CRYPT_ERROR_INVALID, 
				( CRYPT_ERROR_INVALID, SESSION_ERRINFO, 
				  "CA certificate usage restrictions prevent it from being "
				  "used for SCEP" ) );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Request Management Functions						*
*																			*
****************************************************************************/

/* Create a self-signed certificate for signing the request and decrypting
   the response */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createScepCert( INOUT SESSION_INFO *sessionInfoPtr,
						   INOUT SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iNewCert;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	time_t currentTime = getTime();
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

#if 0	/* 20/9/10 This is problematic because if the certificate request 
				   contains attributes then setting the 
				   CRYPT_CERTINFO_CERTREQUEST copies them across to the 
				   certificate, making it an X.509v3 certificate rather than 
				   an X.509v1 one.  To avoid this problem for now we stay 
				   with X.509v3 certificates.

				   To re-enable this, change the ACL entry for
				   CRYPT_CERTINFO_VERSION to
				   'MKPERM_SPECIAL_CERTIFICATES( Rxx_RWx_Rxx_Rxx )',
				   with the comment 'We have to be able to set the version 
				   to 1 for SCEP, which creates a self-signed certificate as 
				   part of the certificate-request process' */
	/* Create a certificate, add the certificate request and other 
	   information required by SCEP to it, and sign it.  To avoid 
	   complications over extension processing we make it an X.509v1 
	   certificate, and to limit the exposure from having it floating around 
	   out there we give it a validity of a day, which is somewhat longer 
	   than required but may be necessary to get around time-zone issues in 
	   which the CA checks the expiry time relative to the time zone that 
	   it's in rather than GMT (although given some of the broken 
	   certificates used with SCEP it seems likely that many CAs do little 
	   to no checking at all) */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionInfoPtr->iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
	if( cryptStatusOK( status ) )
		{
		static const int version = 1;

		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &version, 
								  CRYPT_CERTINFO_VERSION );
		}
#else
	/* Create a certificate, add the certificate request and other 
	   information required by SCEP to it, and sign it.  To limit the 
	   exposure from having it floating around out there we give it a 
	   validity of a day, which is somewhat longer than required but may be 
	   necessary to get around time-zone issues in which the CA checks the 
	   expiry time relative to the time zone that it's in rather than GMT 
	   (although given some of the broken certificates used with SCEP it 
	   seems likely that many CAs do little to no checking at all) 
	   
	   SCEP requires that the certificate serial number match the user name/
	   transaction ID, the spec actually says that the transaction ID should 
	   be a hash of the public key but since it never specifies exactly what 
	   is hashed ("MD5 hash on [sic] public key") this can probably be 
	   anything.  We use the user name, which is required to identify the 
	   pkiUser entry in the CA certificate store */
	setMessageCreateObjectInfo( &createInfo, CRYPT_CERTTYPE_CERTIFICATE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_SETATTRIBUTE,
							  &sessionInfoPtr->iCertRequest,
							  CRYPT_CERTINFO_CERTREQUEST );
#if 0	/* 3/8/10 This seems to have vanished from SCEP drafts after about 
				  draft 16.  When restoring this functionality the special-
				  case attribute handling for SCEP in attr_acl.c has to be 
				  restored as well */
	if( cryptStatusOK( status ) )
		{
		const ATTRIBUTE_LIST *userNamePtr = \
				findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_USERNAME );

		REQUIRES( userNamePtr != NULL );

		/* Set the serial number to the user name/transaction ID as
		   required by SCEP.  This is the only time that we can write a 
		   serial number to a certificate, normally it's set automagically
		   by the certificate-management code */
		setMessageData( &msgData, userNamePtr->value,
						userNamePtr->valueLength );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_SERIALNUMBER );
		}
#endif /* 0 */
	if( cryptStatusOK( status ) )
		{
		static const int keyUsage = CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
									CRYPT_KEYUSAGE_KEYENCIPHERMENT;

		/* Set the certificate usage to signing (to sign the request) and
		   encryption (to decrypt the response).  We've already checked that 
		   these capabilities are available when the key was added to the 
		   session.
		   
		   We delete the attribute before we try and set it in case there 
		   was already one present in the request */
		krnlSendMessage( createInfo.cryptHandle, IMESSAGE_DELETEATTRIBUTE, 
						 NULL, CRYPT_CERTINFO_KEYUSAGE );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE, 
								  ( MESSAGE_CAST ) &keyUsage, 
								  CRYPT_CERTINFO_KEYUSAGE );
		}
#endif /* 1 */
	if( cryptStatusOK( status ) )
		{
		setMessageData( &msgData, ( MESSAGE_CAST ) &currentTime, 
						sizeof( time_t ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_VALIDFROM );
		}
	if( cryptStatusOK( status ) )
		{
		currentTime += 86400;	/* 24 hours */
		status = krnlSendMessage( createInfo.cryptHandle, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_VALIDTO );
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_SETATTRIBUTE, MESSAGE_VALUE_TRUE,
								  CRYPT_CERTINFO_SELFSIGNED );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( createInfo.cryptHandle,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create ephemeral self-signed SCEP "
				  "certificate" ) );
		}

	/* Now that we have a certificate, attach it to the private key.  This 
	   is somewhat ugly since it alters the private key by attaching a 
	   certificate that (as far as the user is concerned) shouldn't really 
	   exist, but we need to do this to allow signing and decryption.  A 
	   side-effect is that it constrains the private-key actions to make 
	   them internal-only since it now has a certificate attached, hopefully 
	   the user won't notice this since the key will have a proper CA-issued 
	   certificate attached to it shortly.

	   To further complicate things, we can't directly attach the newly-
	   created certificate because it already has a public-key context 
	   attached to it, which would result in two keys being associated with 
	   the single certificate.  To resolve this, we create a second copy of 
	   the certificate as a data-only certificate and attach that to the 
	   private key */
	status = krnlSendMessage( createInfo.cryptHandle, IMESSAGE_GETATTRIBUTE, 
							  &iNewCert, CRYPT_IATTRIBUTE_CERTCOPY_DATAONLY );
	if( cryptStatusOK( status ) )
		krnlSendMessage( sessionInfoPtr->privateKey, IMESSAGE_SETDEPENDENT, 
						 &iNewCert, SETDEP_OPTION_NOINCREF );
	if( cryptStatusOK( status ) )
		protocolInfo->iScepCert = createInfo.cryptHandle;
	else
		krnlSendNotifier( createInfo.cryptHandle, IMESSAGE_DECREFCOUNT );
	return( status );
	}

/* Complete the user-supplied PKCS #10 request by adding SCEP-internal
   attributes and information */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int createScepCertRequest( INOUT SESSION_INFO *sessionInfoPtr )
	{
	const ATTRIBUTE_LIST *attributeListPtr = \
				findSessionInfo( sessionInfoPtr->attributeList,
								 CRYPT_SESSINFO_PASSWORD );
	MESSAGE_DATA msgData;
	int status = CRYPT_ERROR_NOTINITED;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Add the password to the PKCS #10 request as a ChallengePassword
	   attribute and sign the request.  We always send this in its
	   ASCII string form even if it's an encoded value because the
	   ChallengePassword attribute has to be a text string */
	if( attributeListPtr != NULL )
		{
		setMessageData( &msgData, attributeListPtr->value,
						attributeListPtr->valueLength );
		status = krnlSendMessage( sessionInfoPtr->iCertRequest, 
								  IMESSAGE_SETATTRIBUTE_S, &msgData, 
								  CRYPT_CERTINFO_CHALLENGEPASSWORD );
		}
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( sessionInfoPtr->iCertRequest,
								  IMESSAGE_CRT_SIGN, NULL,
								  sessionInfoPtr->privateKey );
		}
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't finalise PKCS #10 certificate request" ) );
		}
	return( CRYPT_OK );
	}

/* Create a SCEP request message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int createScepRequest( INOUT SESSION_INFO *sessionInfoPtr,
							  INOUT SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_DATA msgData;
	int dataLength, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Extract the request data into the session buffer */
	setMessageData( &msgData, sessionInfoPtr->receiveBuffer,
					sessionInfoPtr->receiveBufSize );
	status = krnlSendMessage( sessionInfoPtr->iCertRequest,
							  IMESSAGE_CRT_EXPORT, &msgData,
							  CRYPT_CERTFORMAT_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't get PKCS #10 request data from SCEP request "
				  "object" ) );
		}
	DEBUG_DUMP_FILE( "scep_req0", sessionInfoPtr->receiveBuffer, 
					 msgData.length );

	/* Phase 1: Encrypt the data using the CA's key */
	status = envelopeWrap( sessionInfoPtr->receiveBuffer, msgData.length,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, &dataLength, 
						   CRYPT_FORMAT_CMS, CRYPT_CONTENT_NONE, 
						   sessionInfoPtr->iAuthInContext );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't encrypt SCEP request data with CA key" ) );
		}
	DEBUG_DUMP_FILE( "scep_req1", sessionInfoPtr->receiveBuffer, 
					 dataLength );

	/* Create the SCEP signing attributes */
	status = createScepAttributes( sessionInfoPtr, protocolInfo,  
								   &iCmsAttributes, TRUE, CRYPT_OK );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't create SCEP request signing attributes" ) );
		}

	/* Phase 2: Sign the data using the self-signed certificate and SCEP 
	   attributes */
	status = envelopeSign( sessionInfoPtr->receiveBuffer, dataLength,
						   sessionInfoPtr->receiveBuffer, 
						   sessionInfoPtr->receiveBufSize, 
						   &sessionInfoPtr->receiveBufEnd, 
						   CRYPT_CONTENT_NONE, sessionInfoPtr->privateKey, 
						   iCmsAttributes );
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExt( status,
				( status, SESSION_ERRINFO, 
				  "Couldn't sign request data with ephemeral SCEP "
				  "certificate" ) );
		}
	DEBUG_DUMP_FILE( "scep_req2", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Response Management Functions						*
*																			*
****************************************************************************/

/* Check a SCEP response message */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1, 2 ) ) \
static int checkScepResponse( INOUT SESSION_INFO *sessionInfoPtr, 
							  INOUT SCEP_PROTOCOL_INFO *protocolInfo )
	{
	CRYPT_CERTIFICATE iCmsAttributes;
	MESSAGE_CREATEOBJECT_INFO createInfo;
	MESSAGE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_HASHSIZE + 8 ];
	int dataLength, sigResult, value, status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );
	assert( isWritePtr( protocolInfo, sizeof( SCEP_PROTOCOL_INFO ) ) );

	/* Phase 1: Sig-check the data using the CA's key */
	DEBUG_DUMP_FILE( "scep_resp2", sessionInfoPtr->receiveBuffer, 
					 sessionInfoPtr->receiveBufEnd );
	status = envelopeSigCheck( sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufEnd,
							   sessionInfoPtr->receiveBuffer, 
							   sessionInfoPtr->receiveBufSize, &dataLength, 
							   sessionInfoPtr->iAuthInContext, &sigResult,
							   NULL, &iCmsAttributes );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid CMS signed data in CA response" ) );
		}
	DEBUG_DUMP_FILE( "scep_res1", sessionInfoPtr->receiveBuffer, 
					 dataLength );
	if( cryptStatusError( sigResult ) )
		{
		/* The signed data was valid but the signature on it wasn't, this is
		   a different style of error than the previous one */
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( sigResult, 
				( sigResult, SESSION_ERRINFO, 
				  "Bad signature on CA response data" ) );
		}

	/* Check that the returned nonce matches our initial nonce.  It's now
	   identified as a recipient nonce since it's coming from the 
	   responder */
	setMessageData( &msgData, buffer, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCmsAttributes, IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_CERTINFO_SCEP_RECIPIENTNONCE );
	if( cryptStatusError( status ) || \
		msgData.length != protocolInfo->nonceSize || \
		memcmp( buffer, protocolInfo->nonce, protocolInfo->nonceSize ) )
		{
		krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
		retExt( CRYPT_ERROR_SIGNATURE,
				( CRYPT_ERROR_SIGNATURE, SESSION_ERRINFO, 
				  "Returned nonce doesn't match our original nonce" ) );
		}

	/* Check that the operation succeeded */
	status = getScepStatusValue( iCmsAttributes,
								 CRYPT_CERTINFO_SCEP_MESSAGETYPE, &value );
	if( cryptStatusOK( status ) && value != MESSAGETYPE_CERTREP_VALUE )
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		status = getScepStatusValue( iCmsAttributes,
									 CRYPT_CERTINFO_SCEP_PKISTATUS, &value );
	if( cryptStatusOK( status ) && value != MESSAGESTATUS_SUCCESS_VALUE )
		{
		int extValue;

		status = getScepStatusValue( iCmsAttributes,
									 CRYPT_CERTINFO_SCEP_FAILINFO, &extValue );
		if( cryptStatusOK( status ) )
			value = extValue;
		status = CRYPT_ERROR_FAILED;
		}
	krnlSendNotifier( iCmsAttributes, IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "SCEP server reports that certificate issue operation "
				  "failed with error code %d", value ) );
		}

	/* Phase 2: Decrypt the data using our self-signed key */
	status = envelopeUnwrap( sessionInfoPtr->receiveBuffer, dataLength,
							 sessionInfoPtr->receiveBuffer, 
							 sessionInfoPtr->receiveBufSize, &dataLength, 
							 sessionInfoPtr->privateKey );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status,  SESSION_ERRINFO, 
				  "Couldn't decrypt CMS enveloped data in CA response" ) );
		}
	DEBUG_DUMP_FILE( "scep_res0", sessionInfoPtr->receiveBuffer, 
					 dataLength );

	/* Finally, import the returned certificate(s) as a PKCS #7 chain */
	setMessageCreateObjectIndirectInfo( &createInfo,
								sessionInfoPtr->receiveBuffer, dataLength,
								CRYPT_CERTTYPE_CERTCHAIN );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  IMESSAGE_DEV_CREATEOBJECT_INDIRECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		{
		retExt( status, 
				( status, SESSION_ERRINFO, 
				  "Invalid PKCS #7 certificate chain in CA response" ) );
		}
	sessionInfoPtr->iCertResponse = createInfo.cryptHandle;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							SCEP Client Functions							*
*																			*
****************************************************************************/

/* Exchange data with a SCEP server */

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransact( INOUT SESSION_INFO *sessionInfoPtr )
	{
	SCEP_PROTOCOL_INFO protocolInfo;
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* Get the issuing CA certificate via SCEP's bolted-on HTTP GET facility 
	   if necessary */
	if( sessionInfoPtr->iAuthInContext == CRYPT_ERROR )
		{
		status = createAdditionalScepRequest( sessionInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Create the self-signed certificate that we need in order to sign and 
	   decrypt messages */
	initSCEPprotocolInfo( &protocolInfo );
	status = createScepCertRequest( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = createScepCert( sessionInfoPtr, &protocolInfo );
	if( cryptStatusError( status ) )
		return( status );

	/* Get a new certificate from the server */
	status = createScepRequest( sessionInfoPtr, &protocolInfo );
	if( cryptStatusOK( status ) )
		{
#if 0	/* 7/9/10 Why is this commented out? */
		sioctlSetString( &sessionInfoPtr->stream, STREAM_IOCTL_QUERY,
						 "operation=PKIOperation", 22 );
#endif
		status = writePkiDatagram( sessionInfoPtr, SCEP_CONTENT_TYPE,
								   SCEP_CONTENT_TYPE_LEN );
		}
	if( cryptStatusOK( status ) )
		status = readPkiDatagram( sessionInfoPtr );
	if( cryptStatusOK( status ) )
		status = checkScepResponse( sessionInfoPtr, &protocolInfo );
	krnlSendNotifier( protocolInfo.iScepCert, IMESSAGE_DECREFCOUNT );
	protocolInfo.iScepCert = CRYPT_ERROR;
	return( status );
	}

CHECK_RETVAL STDC_NONNULL_ARG( ( 1 ) ) \
static int clientTransactWrapper( INOUT SESSION_INFO *sessionInfoPtr )
	{
	int status;

	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	/* If it's not a plug-and-play PKI session, just pass the call on down
	   to the client transaction function */
	if( !( sessionInfoPtr->sessionSCEP->flags & SCEP_PFLAG_PNPPKI ) )
		return( clientTransact( sessionInfoPtr ) );

	/* We're doing plug-and-play PKI, point the transaction function at the 
	   client-transact function to execute the PnP steps, then reset it back 
	   to the PnP wrapper after we're done */
	sessionInfoPtr->transactFunction = clientTransact;
	status = pnpPkiSession( sessionInfoPtr );
	sessionInfoPtr->transactFunction = clientTransactWrapper;
	return( status );
	}

/****************************************************************************
*																			*
*							Session Access Routines							*
*																			*
****************************************************************************/

STDC_NONNULL_ARG( ( 1 ) ) \
void initSCEPclientProcessing( SESSION_INFO *sessionInfoPtr )
	{
	assert( isWritePtr( sessionInfoPtr, sizeof( SESSION_INFO ) ) );

	sessionInfoPtr->transactFunction = clientTransactWrapper;
	}
#endif /* USE_SCEP */
