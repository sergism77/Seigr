# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: seigr_token.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "seigr_token.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2
import cross_chain_operations_pb2 as cross__chain__operations__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x11seigr_token.proto\x12\x11seigr.seigr_token\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\x1c\x63ross_chain_operations.proto"\xd4\x03\n\nSeigrToken\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x10\n\x08owner_id\x18\x02 \x01(\t\x12\x0f\n\x07\x62\x61lance\x18\x03 \x01(\x04\x12.\n\x06status\x18\x04 \x01(\x0e\x32\x1e.seigr.seigr_token.TokenStatus\x12\x0f\n\x07max_cap\x18\x05 \x01(\x04\x12\x15\n\rcap_threshold\x18\x06 \x01(\x04\x12.\n\ncreated_at\x18\x07 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12.\n\nupdated_at\x18\x08 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12=\n\x08metadata\x18\t \x03(\x0b\x32+.seigr.seigr_token.SeigrToken.MetadataEntry\x12\x19\n\x11\x65\x63o_friendly_flag\x18\n \x01(\x08\x12\x1b\n\x13reward_accumulation\x18\x0b \x01(\x04\x12\x1b\n\x13\x61uthorized_policies\x18\x0c \x03(\t\x12\x14\n\x0ctransferable\x18\r \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xaa\x01\n\x10MintTokenRequest\x12\x10\n\x08owner_id\x18\x01 \x01(\t\x12\x0e\n\x06\x61mount\x18\x02 \x01(\x04\x12\x43\n\x08metadata\x18\x03 \x03(\x0b\x32\x31.seigr.seigr_token.MintTokenRequest.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"G\n\x11MintTokenResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x10\n\x08token_id\x18\x03 \x01(\t"\\\n\x14TransferTokenRequest\x12\x0f\n\x07\x66rom_id\x18\x01 \x01(\t\x12\r\n\x05to_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61mount\x18\x03 \x01(\x04\x12\x14\n\x0creference_id\x18\x04 \x01(\t"9\n\x15TransferTokenResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t"+\n\x17QueryTokenStatusRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t"\x9c\x01\n\x18QueryTokenStatusResponse\x12.\n\x06status\x18\x01 \x01(\x0e\x32\x1e.seigr.seigr_token.TokenStatus\x12\x0f\n\x07\x62\x61lance\x18\x02 \x01(\x04\x12\x0f\n\x07max_cap\x18\x03 \x01(\x04\x12\x1b\n\x13reward_accumulation\x18\x04 \x01(\x04\x12\x11\n\tis_capped\x18\x05 \x01(\x08":\n\x15\x41\x64justTokenCapRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x0f\n\x07new_cap\x18\x02 \x01(\x04"P\n\x16\x41\x64justTokenCapResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x14\n\x0c\x61\x64justed_cap\x18\x03 \x01(\x04"G\n\x18\x44istributeSurplusRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x19\n\x11\x64istribute_amount\x18\x02 \x01(\x04"Y\n\x19\x44istributeSurplusResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x1a\n\x12\x64istributed_amount\x18\x02 \x01(\x04\x12\x0f\n\x07message\x18\x03 \x01(\t"$\n\x10\x42urnTokenRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t"5\n\x11\x42urnTokenResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t"f\n\x1e\x46\x65tchTransactionHistoryRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\r\n\x05limit\x18\x02 \x01(\r\x12#\n\x1binclude_locked_transactions\x18\x03 \x01(\x08"i\n\x1f\x46\x65tchTransactionHistoryResponse\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x34\n\x0ctransactions\x18\x02 \x03(\x0b\x32\x1e.seigr.seigr_token.Transaction"\xb5\x01\n\x0bTransaction\x12\x16\n\x0etransaction_id\x18\x01 \x01(\x04\x12\x0f\n\x07\x66rom_id\x18\x02 \x01(\t\x12\r\n\x05to_id\x18\x03 \x01(\t\x12\x0e\n\x06\x61mount\x18\x04 \x01(\x04\x12-\n\ttimestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12/\n\x04type\x18\x06 \x01(\x0e\x32!.seigr.crosschain.TransactionType*\xa9\x01\n\x0bTokenStatus\x12\x1a\n\x16TOKEN_STATUS_UNDEFINED\x10\x00\x12\x17\n\x13TOKEN_STATUS_ACTIVE\x10\x01\x12\x17\n\x13TOKEN_STATUS_CAPPED\x10\x02\x12\x17\n\x13TOKEN_STATUS_LOCKED\x10\x03\x12\x17\n\x13TOKEN_STATUS_BURNED\x10\x04\x12\x1a\n\x16TOKEN_STATUS_SUSPENDED\x10\x05\x32\xee\x05\n\x11SeigrTokenService\x12V\n\tMintToken\x12#.seigr.seigr_token.MintTokenRequest\x1a$.seigr.seigr_token.MintTokenResponse\x12\x62\n\rTransferToken\x12\'.seigr.seigr_token.TransferTokenRequest\x1a(.seigr.seigr_token.TransferTokenResponse\x12k\n\x10QueryTokenStatus\x12*.seigr.seigr_token.QueryTokenStatusRequest\x1a+.seigr.seigr_token.QueryTokenStatusResponse\x12\x65\n\x0e\x41\x64justTokenCap\x12(.seigr.seigr_token.AdjustTokenCapRequest\x1a).seigr.seigr_token.AdjustTokenCapResponse\x12n\n\x11\x44istributeSurplus\x12+.seigr.seigr_token.DistributeSurplusRequest\x1a,.seigr.seigr_token.DistributeSurplusResponse\x12V\n\tBurnToken\x12#.seigr.seigr_token.BurnTokenRequest\x1a$.seigr.seigr_token.BurnTokenResponse\x12\x80\x01\n\x17\x46\x65tchTransactionHistory\x12\x31.seigr.seigr_token.FetchTransactionHistoryRequest\x1a\x32.seigr.seigr_token.FetchTransactionHistoryResponseb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "seigr_token_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_SEIGRTOKEN_METADATAENTRY"]._loaded_options = None
    _globals["_SEIGRTOKEN_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_MINTTOKENREQUEST_METADATAENTRY"]._loaded_options = None
    _globals["_MINTTOKENREQUEST_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TOKENSTATUS"]._serialized_start = 1972
    _globals["_TOKENSTATUS"]._serialized_end = 2141
    _globals["_SEIGRTOKEN"]._serialized_start = 104
    _globals["_SEIGRTOKEN"]._serialized_end = 572
    _globals["_SEIGRTOKEN_METADATAENTRY"]._serialized_start = 525
    _globals["_SEIGRTOKEN_METADATAENTRY"]._serialized_end = 572
    _globals["_MINTTOKENREQUEST"]._serialized_start = 575
    _globals["_MINTTOKENREQUEST"]._serialized_end = 745
    _globals["_MINTTOKENREQUEST_METADATAENTRY"]._serialized_start = 525
    _globals["_MINTTOKENREQUEST_METADATAENTRY"]._serialized_end = 572
    _globals["_MINTTOKENRESPONSE"]._serialized_start = 747
    _globals["_MINTTOKENRESPONSE"]._serialized_end = 818
    _globals["_TRANSFERTOKENREQUEST"]._serialized_start = 820
    _globals["_TRANSFERTOKENREQUEST"]._serialized_end = 912
    _globals["_TRANSFERTOKENRESPONSE"]._serialized_start = 914
    _globals["_TRANSFERTOKENRESPONSE"]._serialized_end = 971
    _globals["_QUERYTOKENSTATUSREQUEST"]._serialized_start = 973
    _globals["_QUERYTOKENSTATUSREQUEST"]._serialized_end = 1016
    _globals["_QUERYTOKENSTATUSRESPONSE"]._serialized_start = 1019
    _globals["_QUERYTOKENSTATUSRESPONSE"]._serialized_end = 1175
    _globals["_ADJUSTTOKENCAPREQUEST"]._serialized_start = 1177
    _globals["_ADJUSTTOKENCAPREQUEST"]._serialized_end = 1235
    _globals["_ADJUSTTOKENCAPRESPONSE"]._serialized_start = 1237
    _globals["_ADJUSTTOKENCAPRESPONSE"]._serialized_end = 1317
    _globals["_DISTRIBUTESURPLUSREQUEST"]._serialized_start = 1319
    _globals["_DISTRIBUTESURPLUSREQUEST"]._serialized_end = 1390
    _globals["_DISTRIBUTESURPLUSRESPONSE"]._serialized_start = 1392
    _globals["_DISTRIBUTESURPLUSRESPONSE"]._serialized_end = 1481
    _globals["_BURNTOKENREQUEST"]._serialized_start = 1483
    _globals["_BURNTOKENREQUEST"]._serialized_end = 1519
    _globals["_BURNTOKENRESPONSE"]._serialized_start = 1521
    _globals["_BURNTOKENRESPONSE"]._serialized_end = 1574
    _globals["_FETCHTRANSACTIONHISTORYREQUEST"]._serialized_start = 1576
    _globals["_FETCHTRANSACTIONHISTORYREQUEST"]._serialized_end = 1678
    _globals["_FETCHTRANSACTIONHISTORYRESPONSE"]._serialized_start = 1680
    _globals["_FETCHTRANSACTIONHISTORYRESPONSE"]._serialized_end = 1785
    _globals["_TRANSACTION"]._serialized_start = 1788
    _globals["_TRANSACTION"]._serialized_end = 1969
    _globals["_SEIGRTOKENSERVICE"]._serialized_start = 2144
    _globals["_SEIGRTOKENSERVICE"]._serialized_end = 2894
# @@protoc_insertion_point(module_scope)
