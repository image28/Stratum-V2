
/*
//Byte Length Protocol Type Description
1 	BOOL; //  Boolean value. Encoded as an unsigned 1-bit integer, True = 1, False = 0 with 7 additional padding bits in the high positions. x Recipients MUST NOT interpret bits outside of the least significant bit. Senders MAY set bits outside of the least significant bit to any value without any impact on meaning. This allows future use of other bits as flag bits.
1 U8; //  Unsigned integer, 8-bit
2 	U16; //  Unsigned integer, 16-bit, little-endian
3 U24; //  Unsigned integer, 24-bit, little-endian (commonly deserialized as a 32-bit little-endian integer with a trailing implicit most-significant 0-byte).
4 	U32; //  Unsigned integer, 32-bit, little-endian
32 	U256; //  Unsigned integer, 256-bit, little-endian. Often the raw byte output of SHA-256 interpreted as an unsigned integer.
1 +; //  LENGTH 	STR0_255 1-byte length L, unsigned integer 8-bits, followed by a series of L bytes. Allowed range of length is 0 to 255. The string is not null-terminated.
1 +; //  LENGTH 	B0_255 1-byte length L, unsigned integer 8-bits, followed by a sequence of L bytes. Allowed range of length is 0 to 255.
2 +; //  LENGTH 	B0_64K 2-byte length L, unsigned little-endian integer 16-bits, followed by a sequence of L bytes. Allowed range of length is 0 to 65535.
3 +; //  LENGTH B0_16M 3-byte length L, encoded as a U24 above, followed by a sequence of L bytes. Allowed range of length is 0 to 2^24-1.
LENGTH BYTES; //  Arbitrary sequence of LENGTH bytes. See description for how to calculate LENGTH.
32 PUBKEY; //  E d25519 public key
64 SIGNATURE; //  Ed25519 signature
Fixed size; //  T: 1 + LENGTH * size(T) Variable length T: 1 + seq.map(|x| x.length).sum() 	SEQ0_255[T] 1-byte length L, unsigned integer 8-bits, followed by a sequence of L elements of type T. Allowed range of length is 0 to 255.
Fixed size; //  T: 2 + LENGTH * size(T) Variable length T: 2 + seq.map(|x| x.length).sum() 	SEQ0_64K[T] 2-byte length L, unsigned little-endian integer 16-bits, followed by a sequence of L elements of type T. Allowed range of length is 0 to 65535.
};*/

// Data Type Field Name Description
typedef struct stratum_message
{
	U16 extension_type; //  Unique identifier of the extension describing this protocol message. Most significant bit (i.e.bit 15, 0-indexed, aka channel_msg ) indicates a message which is specific to a channel, whereas if the most significant bit is unset, the message is to be interpreted by the immediate receiving device. Note that the channel_msg bit is ignored in the extension lookup, i.e.an extension_type of 0x8ABC is for the same “extension” as 0x0ABC. If the channel_msg bit is set, the first four bytes of the payload field is a 	U32 representing the channel_id this message is destined for (these bytes are repeated in the message framing descriptions below). Note that for the Job Negotiation and Template Distribution Protocols the channel_msg bit is always unset.
	U8 msg_type; //  Unique identifier of the message within the extension_type namespace.
	U24 msg_length; //  Length of the protocol message, not including this header.
	BYTES payload; //  Message-specific payload of length msg_length. If the MSB in extension_type (the channel_msg bit) is set the first four bytes are defined as a 	U32 “channel_id”, though this definition is repeated in the message definitions below and these 4 bytes are included in msg_length.
	Noise_NX(s, rs):; //  -> e <- e, ee , s, es, SIGNATURE_NOISE_MESSAGE
};

// Data Type Field Name Description
typedef struct stratum_cert
{
	U16 version; //  Version of the certificate format
	U32 valid_from; //  Validity start time (unix timestamp)
	U32 not_valid_after; //  Signature is invalid after this point in time (unix timestamp)
	SIGNATURE signature; //  Ed25519 Signature
};

// Data Type Field Name Description
typedef struct stratum_ssl_cert
{
	U16 version; //  Version of the certificate format
	U32 valid_from; //  Validity start time (unix timestamp)
	U32 not_valid_after; //  Signature is invalid after this point in time (unix timestamp)
	PUBKEY public_key; //  static public key of the client
	PUBKEY authority_public_key; //  public key used for verification of the signature
	SIGNATURE signature; //  Ed25519 Signature
};

// Data Type Field Name Description
typedef struct stratum_client
{
U8 protocol; //  0 = Mining Protocol 1 = Job Negotiation Protocol 2 = Template Distribution Protocol 3 = Job Distribution Protocol
	U16 min_version; //  The minimum protocol version the client supports (currently must be 2).
	U16 max_version; //  The maximum protocol version the client supports (currently must be 2).
	U32 flags; //  Flags indicating optional protocol features the client supports. Each protocol from protocol field has its own values/flags.
	STR0_255 endpoint_host; //  ASCII text indicating the hostname or IP address.
	U16 endpoint_port; //  Connecting port value.
	Device information; //
	STR0_255 vendor; //  E.g. “Bitmain”
	STR0_255 hardware_version; //  E.g. “S9i 13.5”
	STR0_255 firmware; //  E.g. “braiins-os-2018-09-22-1-hash”
	STR0_255 device_id; //  Unique identifier of the device as defined by the vendor.
};

// Data Type Field Name Description
typedef struct stratum_version
{
	U16 used_version; //  Selected version proposed by the connecting node that the upstream node supports. This version will be used on the connection for the rest of its life.
	U32 flags; //  Flags indicating optional protocol features the server supports. Each protocol from protocol field has its own values/flags.
};

// Data Type Field Name Description
typedef struct stratum_error
{
	U32 flags; //  Flags indicating features causing an error.
	STR0_255 error_code; //  Human-readable error code(s). See Error Codes section, below.
};

// Data Type Field Name Description
typedef struct stratum_channel_status
{
	U32 channel_id; //  The channel which has changed endpoint.
	/*Bit Field; //  Name Description
	0 REQUIRES_STANDARD_JOBS; //  The downstream node requires standard jobs. It doesn’t understand group channels - it is unable to process extended jobs sent to standard channels through a group channel.
	1 REQUIRES_WORK_SELECTION; //  If set to 1, the client notifies the server that it will send SetCustomMiningJob on this connection.
	2 REQUIRES_VERSION_ROLLING; //  The client requires version rolling for efficiency or correct operation and the server MUST NOT send jobs which do not allow version rolling.
	Bit Field; //  Name Description
	0 REQUIRES_FIXED_VERSION; //  Upstream node will not accept any changes to the version field. Note that if REQUIRES_VERSION_ROLLING was set in the SetupConnection::flags field, this bit MUST NOT be set. Further, if this bit is set, extended jobs MUST NOT indicate support for version rolling.
	1 REQUIRES_EXTENDED_CHANNELS; //  Upstream node will not accept opening of a standard channel.*/
};

// Data Type Field Name Description
typedef struct stratum_request
{
	U32 request_id; //  Client-specified identifier for matching responses from upstream server. The value MUST be connection-wide unique and is not interpreted by the server.
 	user_identity; //  Unconstrained sequence of bytes. Whatever is needed by upstream node to identify/authenticate the client, e.g. “braiinstest.worker1”. Additional restrictions can be imposed by the upstream node (e.g. a pool). It is highly recommended that UTF-8 encoding is used.
	F32 nominal_hash_rate; //  [h/s] Expected hash rate of the device (or cumulative hashrate on the channel if multiple devices are connected downstream) in h/s. Depending on server’s target setting policy, this value can be used for setting a reasonable target for the channel. Proxy MUST send 0.0f when there are no mining devices connected yet.
	U256 max_target; //  Maximum target which can be accepted by the connected device or devices. Server MUST accept the target or respond by sending OpenMiningChannel.Error message.
};

// Data Type Field Name Description
typedef struct stratum_request_response
{
	U32 request_id; //  Client-specified request ID from OpenStandardMiningChannel message, so that the client can pair responses with open channel requests.
	U32 channel_id; //  Newly assigned identifier of the channel, stable for the whole lifetime of the connection. E.g. it is used for broadcasting new jobs by NewExtendedMiningJob.
	U256 target; //  Initial target for the mining channel.
	B0_32 extranonce_prefix; //  Bytes used as implicit first part of extranonce for the scenario when extended job is served by the upstream node for a set of standard channels that belong to the same group.
	U32 group_channel_id; //  Group channel into which the new channel belongs. See SetGroupChannel for details.
};

// Data Type Field Name Description
typedef struct stratum_extranonce
{
 	//<All fields;   from OpenStandardMiningChannel >
	U16 min_extranonce_size; //  Minimum size of extranonce needed by the device/node.
};

// Data Type Field Name Description
typedef struct stratum_sxtranonce_response
{
	U32 request_id; //  Client-specified request ID from OpenExtendedMiningChannel message, so that the client can pair responses with open channel requests.
	U32 channel_id; //  Newly assigned identifier of the channel, stable for the whole lifetime of the connection. E.g. it is used for broadcasting new jobs by NewExtendedMiningJob.
	U256 target; //  Initial target for the mining channel.
	U16 extranonce_size; //  Extranonce size (in bytes) set for the channel.
	B0_32 extranonce_prefix; //  Bytes used as implicit first part of extranonce.
};

// Data Type Field Name Description
typedef struct stratum_error2
{
	U32 request_id; //  Client-specified request ID from OpenMiningChannel message.
	STR0_32 error_code; //  Human-readable error code(s). See Error Codes section, below
};

// Data Type Field Name Description
typedef struct stratum_maxtarget
{
	U32 channel_id; //  Channel identification.
	F32 nominal_hash_rate; //  See Open*Channel for details.
	U256 maximum_target; // Maximum target is changed by server by sending SetTarget. This field is understood as device’s request. There can be some delay between UpdateChannel and corresponding SetTarget messages, based on new job readiness on the server.
};


// Data Type Field Name Description
typedef struct stratum_extranonce_prefix
{
	U32 channel_id; //  Extended or standard channel identifier.
	B0_32 extranonce_prefix; //  Bytes used as implicit first part of extranonce.
};

// Data Type Field Name Description
typedef struct stratum_submit
{
	U32 channel_id; //  Channel identification.
	U32 sequence_number; //  Unique sequential identifier of the submit within the channel.
	U32 job_id; //  Identifier of the job as provided by NewMiningJob or NewExtendedMiningJob message.
	U32 nonce; //  Nonce leading to the hash being submitted.
	U32 ntime; //  The nTime field in the block header. This MUST be greater than or equal to the header_timestamp field in the latest SetNewPrevHash message and lower than or equal to that value plus the number of seconds since the receipt of that message.
	U32 version; //  Full nVersion field.
};

// Data Type Field Name Description
typedef struct stratum_extranonce_coinbase_submit
{
	SubmitSharesStandard message; //  fields>
	B0_31 extranonce; //  Extranonce bytes which need to be added to coinbase to form a fully valid submission (full coinbase = coinbase_tx_prefix + extranonce_prefix + extranonce + coinbase_tx_suffix). The size of the provided extranonce MUST be equal to the negotiated extranonce size from channel opening.
};

// Data Type Field Name Description
typedef struct stratum_status
{
	U32 channel_id; //  Channel identifier.
	U32 last_sequence_number; //  Most recent sequence number with a correct result.
	U32 new_submits_accepted_count; //  Count of new submits acknowledged within this batch.
	U64 new_shares_sum; //  Sum of shares acknowledged within this batch.
};

// Data Type Field Name Description
typedef struct stratum_status_errors
{
	U32 channel_id; //  Channel identifier.
	U32 sequence_number; //  Submission sequence number for which this error is returned.
	STR0_32 error_code; //  Human-readable error code(s). See Error Codes section, below
};

// Data Type Field Name Description
typedef struct stratum_bitcoin_job
{
	U32 channel_id; //  Channel identifier, this must be a standard channel.
	U32 job_id; //  Server’s identification of the mining job. This identifier must be provided to the server when shares are submitted later in the mining process.
	BOOL future_job; //  True if the job is intended for a future SetNewPrevHash message sent on this channel. If False, the job relates to the last sent SetNewPrevHash message on the channel and the miner should start to work on the job immediately.<Bitcoin specific; //  part>
	U32 version; //  Valid version field that reflects the current network consensus. The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node. The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value.
	B32 merkle_root; //  Merkle root field as used in the bitcoin block header.
};

// Data Type Field Name Description
typedef struct stratum_groub_job
{
	U32 channel_id; //  For a group channel, the message is broadcasted to all standard channels belonging to the group. Otherwise, it is addressed to the specified extended channel.
	U32 job_id; //  Server’s identification of the mining job.
	BOOL future_job; //  True if the job is intended for a future SetNewPrevHash message sent on the channel. If False, the job relates to the last sent SetNewPrevHash message on the channel and the miner should start to work on the job immediately.
	U32 version; //  Valid version field that reflects the current network consensus.
	BOOL version_rolling_allowed; //  If set to True, t he general purpose bits of version (as specified in BIP320) can be freely manipulated by the downstream node. The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value. If set to False, the downstream node MUST use version as it is defined by this message.
	SEQ0_255[U256] merkle_path; //  Merkle path hashes ordered from deepest.
	B0_64K coinbase_tx_prefix; //  Prefix part of the coinbase transaction*.
	B0_64K coinbase_tx_suffix; //  Suffix part of the coinbase transaction.
};

// Data Type Field Name Description
typedef struct stratum_job
{
	U32 channel_id; //  Group channel or channel that this prevhash is valid for.
	U32 job_id; //  ID of a job that is to be used for mining with this prevhash. A pool may have provided multiple jobs for the next block height (e.g. an empty block or a block with transactions that are complementary to the set of transactions present in the current block template).
	U256 prev_hash; //  Previous block’s hash, block header field.
	U32 min_ntime; //  Smallest nTime value available for hashing.
	U32 nbits; //  Block header field.
};

// Data Type Field Name Description
typedef struct stratum_blockchain_status
{
	U32 channel_id; //  Extended channel identifier.
	U32 request_id; //  Client-specified identifier for pairing responses.
	B0_255 mining_job_token; //  Token provided by the pool which uniquely identifies the job that the Job Negotiator has negotiated with the pool. See the Job Negotiation Protocol for more details.
	U32 version; //  Valid version field that reflects the current network consensus. The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node.
	U256 prev_hash; //  Previous block’s hash, found in the block header field.
	U32 min_ntime; //  Smallest nTime value available for hashing.
	U32 nbits; //  Block header field.
	U32 coinbase_tx_version; //  The coinbase transaction nVersion field.
	B0_255 coinbase_prefix; //  Up to 8 bytes (not including the length byte) which are to be placed at the beginning of the coinbase field in the coinbase transaction.
	U32 coinbase_tx_input_nSequence; //  The coinbase transaction input’s nSequence field.
	U64 coinbase_tx_value_remaining; //  The value, in satoshis, available for spending in coinbase outputs added by the client. Includes both transaction fees and block subsidy.
	SEQ0_64K[B0_64K] coinbase_tx_outputs; //  Bitcoin transaction outputs to be included as the last outputs in the coinbase transaction.
	U32 coinbase_tx_locktime; //  The locktime field in the coinbase transaction.
	SEQ0_255[U256] merkle_path; //  Merkle path hashes ordered from deepest.
	U16 extranonce_size; //  Size of extranonce in bytes that will be provided by the downstream node.
	BOOL future_job; //  TBD: Can be custom job ever future?
};

// Data Type Field Name Description
typedef struct stratum_coinbase_trans
{
	U32 channel_id; //  Extended channel identifier.
	U32 request_id; //  Client-specified identifier for pairing responses. Value from the request MUST be provided by upstream in the response message.
	U32 job_id; //  Server’s identification of the mining job.
	B0_64K coinbase_tx_prefix; //  Prefix part of the coinbase transaction*.
	B0_64K coinbase_tx_suffix; //  Suffix part of the coinbase transaction.
};

// Data Type Field Name Description
typedef struct stratum_reject
{
	U32 channel_id; //  Extended channel identifier.
	U32 request_id; //  Client-specified identifier for pairing responses. Value from the request MUST be provided by upstream in the response message.
	STR0_32 error_code; //  Reason why the custom job has been rejected.
};

// Data Type Field Name Description
typedef struct stratum_max_height
{
	U32 channel_id; //  Channel identifier.
	U256 maximum_target; //  Maximum value of produced hash that will be accepted by a server to accept shares.
};

// Data Type Field Name Description
typedef struct stratum_reconnect
{
	STR0_255 new_host; //  When empty, downstream node attempts to reconnect to its present host.
	U16 new_port; //  When 0, downstream node attempts to reconnect to its present port.
};

// Data Type Field Name Description
typedef struct stratum_groupids
{
	U32 group_channel_id; //  Identifier of the group where the standard channel belongs.
	SEQ0_64K[U32] channel_ids; //  A sequence of opened standard channel IDs, for which the group channel is being redefined.
};

/*
// Bit Field Name Description
0 REQUIRES_ASYNC_JOB_MINING; //  The Job Negotiator requires that the mining_job_token in AllocateMiningJobToken.Success can be used immediately on a mining connection in SetCustomMiningJob message, even before CommitMiningJob and CommitMiningJob.Success messages have been sent and received. The server MUST only send AllocateMiningJobToken.Success messages with async_mining_allowed set.
*/

// Data Type Field Name Description
typedef struct stratum_auth
{
	STR0_255 user_identifier; //  Unconstrained sequence of bytes. Whatever is needed by the pool to identify/authenticate the client, e.g. “braiinstest”. Additional restrictions can be imposed by the pool. It is highly recommended that UTF-8 encoding is used.
	U32 request_id; //  Unique identifier for pairing the response.
};

// Data Type Field Name Description
typedef struct stratum_auth_response
{
	U32 request_id; //  Unique identifier for pairing the response.
	B0_255 mining_job_token; //  Token that makes the client eligible for committing a mining job for approval/transaction negotiation or for identifying custom mining job on mining connection.
	U32 coinbase_output_max_additional_size; //  The maximum additional serialized bytes which the pool will add in coinbase transaction outputs. See discussion in the Template Distribution Protocol’s CoinbaseOutputDataSize message for more details.
	BOOL async_mining_allowed; //  If true, the mining_job_token can be used immediately on a mining connection in the SetCustomMiningJob message, even before CommitMiningJob and CommitMiningJob.Success messages have been sent and received. If false, Job Negotiator MUST use this token for CommitMiningJob only. This MUST be true when SetupConnection.flags had REQUIRES_ASYNC_JOB_MINING set.
};

// Data Type Field Name Description
typedef struct stratum_big_struct
{
	U32 request_id; //  Unique identifier for pairing the response.
	B0_255 mining_job_token; //  Previously reserved mining job token received by AllocateMiningJobToken.Success.
	U32 version; //  Version header field. To be later modified by BIP320-consistent changes.
	U32 coinbase_tx_version; //  The coinbase transaction nVersion field.
	B0_255 coinbase_prefix; //  Up to 8 bytes (not including the length byte) which are to be placed at the beginning of the coinbase field in the coinbase transaction.
	U32 coinbase_tx_input_nSequence; //  The coinbase transaction input’s nSequence field.
	U64 coinbase_tx_value_remaining; //  The value, in satoshis, available for spending in coinbase outputs added by the client. Includes both transaction fees and block subsidy.
	SEQ0_64K[B0_64K] coinbase_tx_outputs; //  Bitcoin transaction outputs to be included as the last outputs in the coinbase transaction.
	U32 coinbase_tx_locktime; //  The locktime field in the coinbase transaction.
	U16 min_extranonce_size; //  Extranonce size requested to be always available for the mining channel when this job is used on a mining connection.
	U64 tx_short_hash_nonce; //  A unique nonce used to ensure tx_short_hash collisions are uncorrelated across the network.
	SEQ0_64K[ B8; //  ] tx_short_hash_list Sequence of SipHash-2-4(SHA256(transaction_data), tx_short_hash_nonce)) upstream node to check against its mempool. Does not include the coinbase transaction (as there is no corresponding full data for it yet).
	U256 tx_hash_list_hash; //  Hash of the full sequence of SHA256(transaction_data) contained in the transaction_hash_list .
	B0_64K excess_data; //  Extra data which the Pool may require to validate the work (as defined in the Template Distribution Protocol).
};

// Data Type Field Name Description
typedef struct stratum_new_job
{
	U32 request_id; //  Identifier of the original request.
	B0_255 new_mining_job_token; //  Unique identifier provided by the pool of the job that the Job Negotiator has negotiated with the pool. It MAY be the same token as CommitMiningJob::mining_job_token if the pool allows to start mining on not yet negotiated job. If the token is different from the one in the corresponding CommitMiningJob message (irrespective of if the client is already mining using the original token), the client MUST send a SetCustomMiningJob message on each Mining Protocol client which wishes to mine using the negotiated job.
};

// Data Type Field Name Description
typedef struct stratum_error_additional
{
	U32 request_id; //  Identifier of the original request.
	STR0_255 error_code; //
	B0_64K error_details; //  Optional data providing further details to given error.
};

// Data Type Field Name Description
typedef struct stratum_commit_job_response
{
	U32 request_id; //  Unique identifier for pairing the response to the CommitMiningJob message.
};

// Data Type Field Name Description
typedef struct stratum_trans_list_full
{
	U32 request_id; //  Unique identifier for pairing the response to the CommitMiningJob/IdentifyTransactions message.
	SEQ0_64K[U256] tx_hash_list; //  The full list of transaction data hashes used to build the mining job in the corresponding CommitMiningJob message.
};

// Data Type Field Name Description
typedef struct stratum_unrecognised
{
	U32 request_id; //  Identifier of the original CreateMiningJob request.
	SEQ0_64K[U16] unknown_tx_position_list; //  A list of unrecognized transactions that need to be supplied by the Job Negotiator in full . They are specified by their position in the original CommitMiningJob message, 0-indexed not including the coinbase transaction.
};

// Data Type Field Name Description
typedef struct stratum_missing_response
{
	U32 request_id; //  Identifier of the original CreateMiningJob request.
	SEQ0_64K[B0_16M] transaction_list; //  List of full transactions as requested by ProvideMissingTransactions, in the order they were requested in ProvideMissingTransactions.
};

// Data Type Field Name Description
typedef struct stratum_coinbase_additional
{
	U32 coinbase_output_max_additional_size; //  The maximum additional serialized bytes which the pool will add in coinbase transaction outputs.
};

// Data Type Field Name Description
typedef struct stratum_trans_status
{
	U64 template_id; //  Server’s identification of the template. Strictly increasing, the current UNIX time may be used in place of an ID.
	BOOL future_template; //  True if the template is intended for future SetNewPrevHash message sent on the channel. If False, the job relates to the last sent SetNewPrevHash message on the channel and the miner should start to work on the job immediately.
	U32 version; //  Valid header version field that reflects the current network consensus. The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node. The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value.
	U32 coinbase_tx_version; //  The coinbase transaction nVersion field.
	B0_255 coinbase_prefix; //  Up to 8 bytes (not including the length byte) which are to be placed at the beginning of the coinbase field in the coinbase transaction.
	U32 coinbase_tx_input_sequence; //  The coinbase transaction input’s nSequence field.
	U64 coinbase_tx_value_remaining; //  The value, in satoshis, available for spending in coinbase outputs added by the client. Includes both transaction fees and block subsidy.
	U32 coinbase_tx_outputs_count; //  The number of transaction outputs included in coinbase_tx_outputs.
	B0_64K coinbase_tx_outputs; //  Bitcoin transaction outputs to be included as the last outputs in the coinbase transaction.
	U32 coinbase_tx_locktime; //  The locktime field in the coinbase transaction.
	SEQ0_255[U256] merkle_path; //  Merkle path hashes ordered from deepest.
};

// Data Type Field Name Description
typedef struct stratum_template
{
	U64 template_id; //  template _id referenced in a previous NewTemplate message.
	U256 prev_hash; //  Previous block’s hash, as it must appear in the next block’s header.
	U32 header_timestamp; //  The nTime field in the block header at which the client should start (usually current time). This is NOT the minimum valid nTime value.
	U32 nBits; //  Block header field.
	U256 target; //  The maximum double-SHA256 hash value which would represent a valid block. Note that this may be lower than the target implied by nBits in several cases, including weak-block based block propagation.
};

// Data Type Field Name Description
typedef struct stratum_template_response
{
	U64 template_id; //  The template_id corresponding to a NewTemplate message.
};

// Data Type Field Name Description
typedef struct stratum_trans_validation
{
	U64 template_id; //  The template_id corresponding to a NewTemplate/RequestTransactionData message.
	B0_64K excess_data; //  Extra data which the Pool may require to validate the work.
	SEQ0_64K[B0_16M] transaction_list; //  The transaction data, serialized as a series of B0_16M byte arrays.
};

// Data Type Field Name Description
typedef struct stratum_trans_reason
{
	U64 template_id; //  The template_id corresponding to a NewTemplate/RequestTransactionData message.
	STR0_255 error_code; //  Reason why no transaction data has been provided
};

// Data Type Field Name Description
typedef struct stratum_full_trans
{
	U64 template_id; //  The template_id field as it appeared in NewTemplate.
	U32 version; //  The version field in the block header. Bits not defined by BIP320 as additional nonce MUST be the same as they appear in the NewWork message, other bits may be set to any value.
	U32 header_timestamp; //  The nTime field in the block header. This MUST be greater than or equal to the header_timestamp field in the latest SetNewPrevHash message and lower than or equal to that value plus the number of seconds since the receipt of that message.
	U32 header_nonce; //  The nonce field in the header.
	B0_64K coinbase_tx; //  The full serialized coinbase transaction, meeting all the requirements of the NewWork message, above.
};

/*channel_msg bit; //  Message Type (8-bit) Message Name
0 0x00; //  SetupConnection
0 0x01; //  SetupConnection.Success
0 0x02; //  SetupConnection.Error
1 0x03; //  ChannelEndpointChanged*/

/*Mining protocol; //
0 0x10; //  OpenStandardMiningChannel
0 0x11; //  OpenStandardMiningChannel.Success
0 0x12; //  OpenStandardMiningChannel.Error
0 0x13; //  OpenExtendedMiningChannel
0 0x14; //  OpenExtendedMiningChannel.Success
0 0x15; //  OpenExtendedMiningChannel.Error
1 0x16; //  UpdateChannel
1 0x17; //  UpdateChannel.Error
1 0x18; //  CloseChannel
1 0x19; //  SetExtranoncePrefix
1 0x1a; //  SubmitSharesStandard
1 0x1b; //  SubmitSharesExtended
1 0x1c; //  SubmitShares.Success
1 0x1d; //  SubmitShares.Error
1 0x1e; //  NewMiningJob
1 0x1f; //  NewExtendedMiningJob
1 0x20; //  SetNewPrevHash
1 0x21; //  SetTarget
0 0x22; //  SetCustomMiningJob
0 0x23; //  SetCustomMiningJob.Success
0 0x24; //  SetCustomMiningJob.Error
0 0x25; //  Reconnect
0 0x26; //  SetGroupChannel*/

/*Job Negotiation; //  Protocol
0 0x50; //  AllocateMiningJobToken
0 0x51; //  AllocateMiningJobToken.Success
0 0x52; //  AllocateMiningJobToken.Error
0 0x53; //  IdentifyTransactions
0 0x54; //  IdentifyTransactions.Success
0 0x55; //  ProvideMissingTransactions
0 0x56; //  ProvideMissingTransactions.Success*/

/*Template Distribution; //  Protocol
0 0x70; //  CoinbaseOutputDataSize
0 0x71; //  NewTemplate
0 0x72; //  SetNewPrevHash
0 0x73; //  RequestTransactionData
0 0x74; //  RequestTransactionData.Success
0 0x75; //  RequestTransactionData.Error
0 0x76; //  SubmitSolution*/

//Extension Name; //  Extension Type (no channel_msg bit) Description / BIP
//Hashing Power; //  Information

// Data Type Field Name Description
typedef struct stratum_devices
{
	U32 aggregated_device_count; //  Number of aggregated devices on the channel. An end mining device must send 1. A proxy can send 0 when there are no connections to it yet (in aggregating mode)
};
