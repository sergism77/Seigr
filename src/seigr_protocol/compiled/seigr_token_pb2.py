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
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    2,
    '',
    'seigr_token.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import cross_chain_operations_pb2 as cross__chain__operations__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11seigr_token.proto\x12\x05seigr\x1a\x1c\x63ross_chain_operations.proto\"\x88\x02\n\nSeigrToken\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x10\n\x08owner_id\x18\x02 \x01(\t\x12\x0f\n\x07\x62\x61lance\x18\x03 \x01(\x04\x12\"\n\x06status\x18\x04 \x01(\x0e\x32\x12.seigr.TokenStatus\x12\x0f\n\x07max_cap\x18\x05 \x01(\x04\x12\x15\n\rcap_threshold\x18\x06 \x01(\x04\x12\x15\n\rcreation_date\x18\x07 \x01(\t\x12\x31\n\x08metadata\x18\x08 \x03(\x0b\x32\x1f.seigr.SeigrToken.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"4\n\x10MintTokenRequest\x12\x10\n\x08owner_id\x18\x01 \x01(\t\x12\x0e\n\x06\x61mount\x18\x02 \x01(\x04\"5\n\x11MintTokenResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"F\n\x14TransferTokenRequest\x12\x0f\n\x07\x66rom_id\x18\x01 \x01(\t\x12\r\n\x05to_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61mount\x18\x03 \x01(\x04\"9\n\x15TransferTokenResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"+\n\x17\x43heckTokenStatusRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\"\x8b\x01\n\x18\x43heckTokenStatusResponse\x12\"\n\x06status\x18\x01 \x01(\x0e\x32\x12.seigr.TokenStatus\x12\x0f\n\x07\x62\x61lance\x18\x02 \x01(\x04\x12\x0f\n\x07max_cap\x18\x03 \x01(\x04\x12\x11\n\tis_capped\x18\x04 \x01(\x08\x12\x16\n\x0esurplus_amount\x18\x05 \x01(\x04\":\n\x15\x41\x64justTokenCapRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x0f\n\x07new_cap\x18\x02 \x01(\x04\"P\n\x16\x41\x64justTokenCapResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x14\n\x0c\x61\x64justed_cap\x18\x03 \x01(\x04\"G\n\x18\x44istributeSurplusRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\x19\n\x11\x64istribute_amount\x18\x02 \x01(\x04\"Y\n\x19\x44istributeSurplusResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x1a\n\x12\x64istributed_amount\x18\x02 \x01(\x04\x12\x0f\n\x07message\x18\x03 \x01(\t\"d\n\x1cGetTransactionHistoryRequest\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12\r\n\x05limit\x18\x02 \x01(\r\x12#\n\x1binclude_locked_transactions\x18\x03 \x01(\x08\"[\n\x1dGetTransactionHistoryResponse\x12\x10\n\x08token_id\x18\x01 \x01(\t\x12(\n\x0ctransactions\x18\x02 \x03(\x0b\x32\x12.seigr.Transaction\"\x8e\x01\n\x0bTransaction\x12\x16\n\x0etransaction_id\x18\x01 \x01(\x04\x12\x0f\n\x07\x66rom_id\x18\x02 \x01(\t\x12\r\n\x05to_id\x18\x03 \x01(\t\x12\x0e\n\x06\x61mount\x18\x04 \x01(\x04\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12$\n\x04type\x18\x06 \x01(\x0e\x32\x16.seigr.TransactionType*X\n\x0bTokenStatus\x12\x17\n\x13TOKEN_STATUS_ACTIVE\x10\x00\x12\x17\n\x13TOKEN_STATUS_CAPPED\x10\x01\x12\x17\n\x13TOKEN_STATUS_LOCKED\x10\x02\x32\xff\x03\n\x11SeigrTokenService\x12>\n\tMintToken\x12\x17.seigr.MintTokenRequest\x1a\x18.seigr.MintTokenResponse\x12J\n\rTransferToken\x12\x1b.seigr.TransferTokenRequest\x1a\x1c.seigr.TransferTokenResponse\x12S\n\x10\x43heckTokenStatus\x12\x1e.seigr.CheckTokenStatusRequest\x1a\x1f.seigr.CheckTokenStatusResponse\x12M\n\x0e\x41\x64justTokenCap\x12\x1c.seigr.AdjustTokenCapRequest\x1a\x1d.seigr.AdjustTokenCapResponse\x12V\n\x11\x44istributeSurplus\x12\x1f.seigr.DistributeSurplusRequest\x1a .seigr.DistributeSurplusResponse\x12\x62\n\x15GetTransactionHistory\x12#.seigr.GetTransactionHistoryRequest\x1a$.seigr.GetTransactionHistoryResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'seigr_token_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_SEIGRTOKEN_METADATAENTRY']._loaded_options = None
  _globals['_SEIGRTOKEN_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_TOKENSTATUS']._serialized_start=1398
  _globals['_TOKENSTATUS']._serialized_end=1486
  _globals['_SEIGRTOKEN']._serialized_start=59
  _globals['_SEIGRTOKEN']._serialized_end=323
  _globals['_SEIGRTOKEN_METADATAENTRY']._serialized_start=276
  _globals['_SEIGRTOKEN_METADATAENTRY']._serialized_end=323
  _globals['_MINTTOKENREQUEST']._serialized_start=325
  _globals['_MINTTOKENREQUEST']._serialized_end=377
  _globals['_MINTTOKENRESPONSE']._serialized_start=379
  _globals['_MINTTOKENRESPONSE']._serialized_end=432
  _globals['_TRANSFERTOKENREQUEST']._serialized_start=434
  _globals['_TRANSFERTOKENREQUEST']._serialized_end=504
  _globals['_TRANSFERTOKENRESPONSE']._serialized_start=506
  _globals['_TRANSFERTOKENRESPONSE']._serialized_end=563
  _globals['_CHECKTOKENSTATUSREQUEST']._serialized_start=565
  _globals['_CHECKTOKENSTATUSREQUEST']._serialized_end=608
  _globals['_CHECKTOKENSTATUSRESPONSE']._serialized_start=611
  _globals['_CHECKTOKENSTATUSRESPONSE']._serialized_end=750
  _globals['_ADJUSTTOKENCAPREQUEST']._serialized_start=752
  _globals['_ADJUSTTOKENCAPREQUEST']._serialized_end=810
  _globals['_ADJUSTTOKENCAPRESPONSE']._serialized_start=812
  _globals['_ADJUSTTOKENCAPRESPONSE']._serialized_end=892
  _globals['_DISTRIBUTESURPLUSREQUEST']._serialized_start=894
  _globals['_DISTRIBUTESURPLUSREQUEST']._serialized_end=965
  _globals['_DISTRIBUTESURPLUSRESPONSE']._serialized_start=967
  _globals['_DISTRIBUTESURPLUSRESPONSE']._serialized_end=1056
  _globals['_GETTRANSACTIONHISTORYREQUEST']._serialized_start=1058
  _globals['_GETTRANSACTIONHISTORYREQUEST']._serialized_end=1158
  _globals['_GETTRANSACTIONHISTORYRESPONSE']._serialized_start=1160
  _globals['_GETTRANSACTIONHISTORYRESPONSE']._serialized_end=1251
  _globals['_TRANSACTION']._serialized_start=1254
  _globals['_TRANSACTION']._serialized_end=1396
  _globals['_SEIGRTOKENSERVICE']._serialized_start=1489
  _globals['_SEIGRTOKENSERVICE']._serialized_end=2000
# @@protoc_insertion_point(module_scope)
