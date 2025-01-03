# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: treasury_management.proto
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
    'treasury_management.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import mycelith_voting_pb2 as mycelith__voting__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x19treasury_management.proto\x12\x05seigr\x1a\x15mycelith_voting.proto\"\xa4\x02\n\x0cTreasuryPool\x12\x0f\n\x07pool_id\x18\x01 \x01(\t\x12\x0f\n\x07purpose\x18\x02 \x01(\t\x12\x0f\n\x07\x62\x61lance\x18\x03 \x01(\x04\x12\x36\n\x13\x64istribution_policy\x18\x04 \x01(\x0e\x32\x19.seigr.DistributionPolicy\x12\x12\n\ncreated_at\x18\x05 \x01(\t\x12\x33\n\x08metadata\x18\x06 \x03(\x0b\x32!.seigr.TreasuryPool.MetadataEntry\x12\x17\n\x0f\x61llocated_funds\x18\x07 \x01(\x04\x12\x16\n\x0ereserved_funds\x18\x08 \x01(\x04\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x84\x03\n\x0e\x46undingRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x0f\n\x07purpose\x18\x02 \x01(\t\x12\x18\n\x10requested_amount\x18\x03 \x01(\x04\x12,\n\x0e\x66unding_status\x18\x04 \x01(\x0e\x32\x14.seigr.FundingStatus\x12)\n\rvoting_layers\x18\x05 \x03(\x0b\x32\x12.seigr.VotingLayer\x12\x14\n\x0crequester_id\x18\x06 \x01(\t\x12\x11\n\ttimestamp\x18\x07 \x01(\t\x12\x14\n\x0clast_updated\x18\x08 \x01(\t\x12\x35\n\x08metadata\x18\t \x03(\x0b\x32#.seigr.FundingRequest.MetadataEntry\x12\x17\n\x0f\x61pproved_amount\x18\n \x01(\x04\x12\x1a\n\x12\x61pproval_timestamp\x18\x0b \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"[\n\x18\x46undingSubmissionRequest\x12\x0f\n\x07purpose\x18\x01 \x01(\t\x12\x18\n\x10requested_amount\x18\x02 \x01(\x04\x12\x14\n\x0crequester_id\x18\x03 \x01(\t\"Q\n\x19\x46undingSubmissionResponse\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x0f\n\x07success\x18\x02 \x01(\x08\x12\x0f\n\x07message\x18\x03 \x01(\t\"a\n\x16\x46undingApprovalRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x10\n\x08voter_id\x18\x02 \x01(\t\x12!\n\x06\x63hoice\x18\x03 \x01(\x0e\x32\x11.seigr.VoteChoice\";\n\x17\x46undingApprovalResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"k\n\x14TransferFundsRequest\x12\x0f\n\x07pool_id\x18\x01 \x01(\t\x12\x0e\n\x06\x61mount\x18\x02 \x01(\x04\x12\x19\n\x11recipient_address\x18\x03 \x01(\t\x12\x17\n\x0ftransfer_reason\x18\x04 \x01(\t\"9\n\x15TransferFundsResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"R\n\x18GetFundingHistoryRequest\x12\x0f\n\x07pool_id\x18\x01 \x01(\t\x12\r\n\x05limit\x18\x02 \x01(\r\x12\x16\n\x0einclude_denied\x18\x03 \x01(\x08\"u\n\x19GetFundingHistoryResponse\x12\x0f\n\x07pool_id\x18\x01 \x01(\t\x12/\n\x10\x66unding_requests\x18\x02 \x03(\x0b\x32\x15.seigr.FundingRequest\x12\x16\n\x0etotal_requests\x18\x03 \x01(\r\"u\n\x1fUpdateDistributionPolicyRequest\x12\x0f\n\x07pool_id\x18\x01 \x01(\t\x12-\n\nnew_policy\x18\x02 \x01(\x0e\x32\x19.seigr.DistributionPolicy\x12\x12\n\nupdated_by\x18\x03 \x01(\t\"w\n UpdateDistributionPolicyResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x31\n\x0e\x61pplied_policy\x18\x03 \x01(\x0e\x32\x19.seigr.DistributionPolicy*\x93\x01\n\x12\x44istributionPolicy\x12(\n$DISTRIBUTION_POLICY_FIXED_ALLOCATION\x10\x00\x12(\n$DISTRIBUTION_POLICY_PERCENTAGE_BASED\x10\x01\x12)\n%DISTRIBUTION_POLICY_VOTING_DETERMINED\x10\x02*\xab\x01\n\rFundingStatus\x12\x1a\n\x16\x46UNDING_STATUS_PENDING\x10\x00\x12\x1b\n\x17\x46UNDING_STATUS_APPROVED\x10\x01\x12\x19\n\x15\x46UNDING_STATUS_DENIED\x10\x02\x12%\n!FUNDING_STATUS_PARTIALLY_APPROVED\x10\x03\x12\x1f\n\x1b\x46UNDING_STATUS_UNDER_REVIEW\x10\x04\x32\xe0\x03\n\x19TreasuryManagementService\x12Y\n\x14SubmitFundingRequest\x12\x1f.seigr.FundingSubmissionRequest\x1a .seigr.FundingSubmissionResponse\x12W\n\x16ProcessFundingApproval\x12\x1d.seigr.FundingApprovalRequest\x1a\x1e.seigr.FundingApprovalResponse\x12J\n\rTransferFunds\x12\x1b.seigr.TransferFundsRequest\x1a\x1c.seigr.TransferFundsResponse\x12V\n\x11GetFundingHistory\x12\x1f.seigr.GetFundingHistoryRequest\x1a .seigr.GetFundingHistoryResponse\x12k\n\x18UpdateDistributionPolicy\x12&.seigr.UpdateDistributionPolicyRequest\x1a\'.seigr.UpdateDistributionPolicyResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'treasury_management_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_TREASURYPOOL_METADATAENTRY']._loaded_options = None
  _globals['_TREASURYPOOL_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_FUNDINGREQUEST_METADATAENTRY']._loaded_options = None
  _globals['_FUNDINGREQUEST_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_DISTRIBUTIONPOLICY']._serialized_start=1693
  _globals['_DISTRIBUTIONPOLICY']._serialized_end=1840
  _globals['_FUNDINGSTATUS']._serialized_start=1843
  _globals['_FUNDINGSTATUS']._serialized_end=2014
  _globals['_TREASURYPOOL']._serialized_start=60
  _globals['_TREASURYPOOL']._serialized_end=352
  _globals['_TREASURYPOOL_METADATAENTRY']._serialized_start=305
  _globals['_TREASURYPOOL_METADATAENTRY']._serialized_end=352
  _globals['_FUNDINGREQUEST']._serialized_start=355
  _globals['_FUNDINGREQUEST']._serialized_end=743
  _globals['_FUNDINGREQUEST_METADATAENTRY']._serialized_start=305
  _globals['_FUNDINGREQUEST_METADATAENTRY']._serialized_end=352
  _globals['_FUNDINGSUBMISSIONREQUEST']._serialized_start=745
  _globals['_FUNDINGSUBMISSIONREQUEST']._serialized_end=836
  _globals['_FUNDINGSUBMISSIONRESPONSE']._serialized_start=838
  _globals['_FUNDINGSUBMISSIONRESPONSE']._serialized_end=919
  _globals['_FUNDINGAPPROVALREQUEST']._serialized_start=921
  _globals['_FUNDINGAPPROVALREQUEST']._serialized_end=1018
  _globals['_FUNDINGAPPROVALRESPONSE']._serialized_start=1020
  _globals['_FUNDINGAPPROVALRESPONSE']._serialized_end=1079
  _globals['_TRANSFERFUNDSREQUEST']._serialized_start=1081
  _globals['_TRANSFERFUNDSREQUEST']._serialized_end=1188
  _globals['_TRANSFERFUNDSRESPONSE']._serialized_start=1190
  _globals['_TRANSFERFUNDSRESPONSE']._serialized_end=1247
  _globals['_GETFUNDINGHISTORYREQUEST']._serialized_start=1249
  _globals['_GETFUNDINGHISTORYREQUEST']._serialized_end=1331
  _globals['_GETFUNDINGHISTORYRESPONSE']._serialized_start=1333
  _globals['_GETFUNDINGHISTORYRESPONSE']._serialized_end=1450
  _globals['_UPDATEDISTRIBUTIONPOLICYREQUEST']._serialized_start=1452
  _globals['_UPDATEDISTRIBUTIONPOLICYREQUEST']._serialized_end=1569
  _globals['_UPDATEDISTRIBUTIONPOLICYRESPONSE']._serialized_start=1571
  _globals['_UPDATEDISTRIBUTIONPOLICYRESPONSE']._serialized_end=1690
  _globals['_TREASURYMANAGEMENTSERVICE']._serialized_start=2017
  _globals['_TREASURYMANAGEMENTSERVICE']._serialized_end=2497
# @@protoc_insertion_point(module_scope)
