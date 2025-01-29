# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: temporal.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "temporal.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2
import lineage_pb2 as lineage__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0etemporal.proto\x12\x0eseigr.temporal\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\rlineage.proto"\xf2\x02\n\x0fTemporalHistory\x12\x12\n\nhistory_id\x18\x01 \x01(\t\x12\x35\n\x0ftemporal_layers\x18\x02 \x03(\x0b\x32\x1c.seigr.lineage.TemporalLayer\x12\x12\n\ncreated_by\x18\x03 \x01(\t\x12.\n\ncreated_at\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x34\n\x10last_modified_at\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12?\n\x08metadata\x18\x06 \x03(\x0b\x32-.seigr.temporal.TemporalHistory.MetadataEntry\x12\x15\n\rversion_count\x18\x07 \x01(\x05\x12\x11\n\tis_active\x18\x08 \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xf2\x02\n\x0fLineageTracking\x12\x12\n\nlineage_id\x18\x01 \x01(\t\x12\x17\n\x0f\x61ncestor_hashes\x18\x02 \x03(\t\x12\x19\n\x11\x64\x65scendant_hashes\x18\x03 \x03(\t\x12\x35\n\x11original_creation\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12N\n\x10lineage_metadata\x18\x05 \x03(\x0b\x32\x34.seigr.temporal.LineageTracking.LineageMetadataEntry\x12\x17\n\x0fintegrity_check\x18\x06 \x01(\t\x12\x10\n\x08\x61rchived\x18\x07 \x01(\x08\x12\x17\n\x0f\x65volution_depth\x18\x08 \x01(\x05\x12\x14\n\x0clineage_type\x18\t \x01(\t\x1a\x36\n\x14LineageMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xcb\x02\n\x17TemporalSnapshotRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x12\n\nsegment_id\x18\x02 \x01(\t\x12\x34\n\x10target_timestamp\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x13\n\x0b\x65xact_match\x18\x04 \x01(\x08\x12\x14\n\x0crequested_by\x18\x05 \x01(\t\x12V\n\x10request_metadata\x18\x06 \x03(\x0b\x32<.seigr.temporal.TemporalSnapshotRequest.RequestMetadataEntry\x12\x17\n\x0frequest_purpose\x18\x07 \x01(\t\x1a\x36\n\x14RequestMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x91\x03\n\x18TemporalSnapshotResponse\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x34\n\x0esnapshot_layer\x18\x02 \x01(\x0b\x32\x1c.seigr.lineage.TemporalLayer\x12\x0f\n\x07success\x18\x03 \x01(\x08\x12\x15\n\rerror_message\x18\x04 \x01(\t\x12Y\n\x11response_metadata\x18\x05 \x03(\x0b\x32>.seigr.temporal.TemporalSnapshotResponse.ResponseMetadataEntry\x12\x37\n\x13retrieved_timestamp\x18\x06 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x1d\n\x15retrieval_duration_ms\x18\x07 \x01(\x03\x12\x17\n\x0fsnapshot_source\x18\x08 \x01(\t\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xbc\x02\n\x14TemporalMergeRequest\x12\x10\n\x08merge_id\x18\x01 \x01(\t\x12\x11\n\tlayer_ids\x18\x02 \x03(\t\x12\x11\n\ttarget_id\x18\x03 \x01(\t\x12\x14\n\x0cinitiated_by\x18\x04 \x01(\t\x12\x35\n\nmerge_type\x18\x05 \x01(\x0e\x32!.seigr.temporal.TemporalMergeType\x12O\n\x0emerge_metadata\x18\x06 \x03(\x0b\x32\x37.seigr.temporal.TemporalMergeRequest.MergeMetadataEntry\x12\x18\n\x10retain_originals\x18\x07 \x01(\x08\x1a\x34\n\x12MergeMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x96\x02\n\x15TemporalMergeResponse\x12\x10\n\x08merge_id\x18\x01 \x01(\t\x12\x0f\n\x07success\x18\x02 \x01(\x08\x12\x17\n\x0fmerged_layer_id\x18\x03 \x01(\t\x12\x15\n\rerror_message\x18\x04 \x01(\t\x12V\n\x11response_metadata\x18\x05 \x03(\x0b\x32;.seigr.temporal.TemporalMergeResponse.ResponseMetadataEntry\x12\x19\n\x11merge_duration_ms\x18\x06 \x01(\x03\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x9e\x03\n\x0eTemporalPolicy\x12\x11\n\tpolicy_id\x18\x01 \x01(\t\x12\x13\n\x0bpolicy_name\x18\x02 \x01(\t\x12\x1f\n\x17retention_duration_days\x18\x03 \x01(\x05\x12 \n\x18\x65nable_automatic_merging\x18\x04 \x01(\x08\x12\x1c\n\x14merge_frequency_days\x18\x05 \x01(\x05\x12 \n\x18\x65nable_snapshot_deletion\x18\x06 \x01(\x08\x12\x19\n\x11\x64\x65letion_criteria\x18\x07 \x01(\t\x12K\n\x0fpolicy_metadata\x18\x08 \x03(\x0b\x32\x32.seigr.temporal.TemporalPolicy.PolicyMetadataEntry\x12\x12\n\ncreated_by\x18\t \x01(\t\x12.\n\ncreated_at\x18\n \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x1a\x35\n\x13PolicyMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x9c\x02\n\x10TemporalAuditLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x13\n\x0btemporal_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61\x63tion\x18\x03 \x01(\t\x12\x11\n\taction_by\x18\x04 \x01(\t\x12-\n\ttimestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12K\n\x0e\x61udit_metadata\x18\x06 \x03(\x0b\x32\x33.seigr.temporal.TemporalAuditLog.AuditMetadataEntry\x12\x0e\n\x06status\x18\x07 \x01(\t\x1a\x34\n\x12\x41uditMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\x85\x01\n\x11TemporalMergeType\x12\x1c\n\x18TEMPORAL_MERGE_UNDEFINED\x10\x00\x12\x18\n\x14TEMPORAL_MERGE_UNION\x10\x01\x12\x1a\n\x16TEMPORAL_MERGE_OVERLAY\x10\x02\x12\x1c\n\x18TEMPORAL_MERGE_RECONCILE\x10\x03\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "temporal_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_TEMPORALHISTORY_METADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALHISTORY_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_LINEAGETRACKING_LINEAGEMETADATAENTRY"]._loaded_options = None
    _globals["_LINEAGETRACKING_LINEAGEMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALSNAPSHOTREQUEST_REQUESTMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALSNAPSHOTREQUEST_REQUESTMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALSNAPSHOTRESPONSE_RESPONSEMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALSNAPSHOTRESPONSE_RESPONSEMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALMERGEREQUEST_MERGEMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALMERGEREQUEST_MERGEMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALMERGERESPONSE_RESPONSEMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALMERGERESPONSE_RESPONSEMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALPOLICY_POLICYMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALPOLICY_POLICYMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALAUDITLOG_AUDITMETADATAENTRY"]._loaded_options = None
    _globals["_TEMPORALAUDITLOG_AUDITMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_TEMPORALMERGETYPE"]._serialized_start = 2871
    _globals["_TEMPORALMERGETYPE"]._serialized_end = 3004
    _globals["_TEMPORALHISTORY"]._serialized_start = 83
    _globals["_TEMPORALHISTORY"]._serialized_end = 453
    _globals["_TEMPORALHISTORY_METADATAENTRY"]._serialized_start = 406
    _globals["_TEMPORALHISTORY_METADATAENTRY"]._serialized_end = 453
    _globals["_LINEAGETRACKING"]._serialized_start = 456
    _globals["_LINEAGETRACKING"]._serialized_end = 826
    _globals["_LINEAGETRACKING_LINEAGEMETADATAENTRY"]._serialized_start = 772
    _globals["_LINEAGETRACKING_LINEAGEMETADATAENTRY"]._serialized_end = 826
    _globals["_TEMPORALSNAPSHOTREQUEST"]._serialized_start = 829
    _globals["_TEMPORALSNAPSHOTREQUEST"]._serialized_end = 1160
    _globals["_TEMPORALSNAPSHOTREQUEST_REQUESTMETADATAENTRY"]._serialized_start = 1106
    _globals["_TEMPORALSNAPSHOTREQUEST_REQUESTMETADATAENTRY"]._serialized_end = 1160
    _globals["_TEMPORALSNAPSHOTRESPONSE"]._serialized_start = 1163
    _globals["_TEMPORALSNAPSHOTRESPONSE"]._serialized_end = 1564
    _globals["_TEMPORALSNAPSHOTRESPONSE_RESPONSEMETADATAENTRY"]._serialized_start = 1509
    _globals["_TEMPORALSNAPSHOTRESPONSE_RESPONSEMETADATAENTRY"]._serialized_end = 1564
    _globals["_TEMPORALMERGEREQUEST"]._serialized_start = 1567
    _globals["_TEMPORALMERGEREQUEST"]._serialized_end = 1883
    _globals["_TEMPORALMERGEREQUEST_MERGEMETADATAENTRY"]._serialized_start = 1831
    _globals["_TEMPORALMERGEREQUEST_MERGEMETADATAENTRY"]._serialized_end = 1883
    _globals["_TEMPORALMERGERESPONSE"]._serialized_start = 1886
    _globals["_TEMPORALMERGERESPONSE"]._serialized_end = 2164
    _globals["_TEMPORALMERGERESPONSE_RESPONSEMETADATAENTRY"]._serialized_start = 1509
    _globals["_TEMPORALMERGERESPONSE_RESPONSEMETADATAENTRY"]._serialized_end = 1564
    _globals["_TEMPORALPOLICY"]._serialized_start = 2167
    _globals["_TEMPORALPOLICY"]._serialized_end = 2581
    _globals["_TEMPORALPOLICY_POLICYMETADATAENTRY"]._serialized_start = 2528
    _globals["_TEMPORALPOLICY_POLICYMETADATAENTRY"]._serialized_end = 2581
    _globals["_TEMPORALAUDITLOG"]._serialized_start = 2584
    _globals["_TEMPORALAUDITLOG"]._serialized_end = 2868
    _globals["_TEMPORALAUDITLOG_AUDITMETADATAENTRY"]._serialized_start = 2816
    _globals["_TEMPORALAUDITLOG_AUDITMETADATAENTRY"]._serialized_end = 2868
# @@protoc_insertion_point(module_scope)
