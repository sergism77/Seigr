# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: lineage.proto
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
    'lineage.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import segment_metadata_pb2 as segment__metadata__pb2
from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2
import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rlineage.proto\x12\rseigr.lineage\x1a\x16segment_metadata.proto\x1a\x1fgoogle/protobuf/timestamp.proto\x1a\x0c\x63ommon.proto\"\xa5\x07\n\x07Lineage\x12\x12\n\nlineage_id\x18\x01 \x01(\t\x12\x12\n\ncreator_id\x18\x02 \x01(\t\x12\x14\n\x0c\x63urrent_hash\x18\x03 \x01(\t\x12\x16\n\x0e\x66ormat_version\x18\x04 \x01(\t\x12\x30\n\x0clineage_type\x18\x05 \x01(\x0e\x32\x1a.seigr.lineage.LineageType\x12,\n\x06status\x18\x06 \x01(\x0e\x32\x1c.seigr.lineage.LineageStatus\x12+\n\x07\x65ntries\x18\x07 \x03(\x0b\x32\x1a.seigr.common.LineageEntry\x12\x1a\n\x12integrity_checksum\x18\x08 \x01(\t\x12\x36\n\x08metadata\x18\t \x03(\x0b\x32$.seigr.lineage.Lineage.MetadataEntry\x12\x19\n\x11parent_lineage_id\x18\n \x01(\t\x12\x35\n\x11\x61rchive_timestamp\x18\x0b \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x18\n\x10\x61ssociated_files\x18\x0c \x03(\t\x12\x1c\n\x14network_reference_id\x18\r \x01(\t\x12\x1a\n\x12\x61\x63\x63\x65ss_permissions\x18\x0e \x03(\t\x12\x17\n\x0flinked_lineages\x18\x0f \x03(\t\x12\x31\n\rlast_modified\x18\x10 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12G\n\x11\x61\x64\x61ptive_triggers\x18\x11 \x03(\x0b\x32,.seigr.lineage.Lineage.AdaptiveTriggersEntry\x12\x1a\n\x12\x64\x65precation_policy\x18\x12 \x01(\t\x12N\n\x15network_protocol_data\x18\x13 \x03(\x0b\x32/.seigr.lineage.Lineage.NetworkProtocolDataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1aO\n\x15\x41\x64\x61ptiveTriggersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12%\n\x05value\x18\x02 \x01(\x0b\x32\x16.seigr.common.Feedback:\x02\x38\x01\x1a:\n\x18NetworkProtocolDataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xdb\x03\n\x18LineageValidationSummary\x12\x15\n\rvalidation_id\x18\x01 \x01(\t\x12\x12\n\nlineage_id\x18\x02 \x01(\t\x12\x1d\n\x15validation_successful\x18\x03 \x01(\x08\x12\x10\n\x08warnings\x18\x04 \x03(\t\x12\x0e\n\x06\x65rrors\x18\x05 \x03(\t\x12\x38\n\x14validation_timestamp\x18\x06 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x14\n\x0cvalidated_by\x18\x07 \x01(\t\x12\x1a\n\x12integrity_checksum\x18\x08 \x01(\t\x12\\\n\x13validation_metadata\x18\t \x03(\x0b\x32?.seigr.lineage.LineageValidationSummary.ValidationMetadataEntry\x12\x1a\n\x12recommended_action\x18\n \x01(\t\x12\x19\n\x11\x64\x65pendency_checks\x18\x0b \x03(\t\x12\x17\n\x0frollback_advice\x18\x0c \x01(\t\x1a\x39\n\x17ValidationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xef\x02\n\x11LineageAuditTrail\x12\x10\n\x08\x61udit_id\x18\x01 \x01(\t\x12\x12\n\nlineage_id\x18\x02 \x01(\t\x12\x19\n\x11\x65vent_description\x18\x03 \x01(\t\x12\x14\n\x0cperformed_by\x18\x04 \x01(\t\x12\x33\n\x0f\x65vent_timestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x14\n\x0c\x65vent_status\x18\x06 \x01(\t\x12K\n\x0e\x61udit_metadata\x18\x07 \x03(\x0b\x32\x33.seigr.lineage.LineageAuditTrail.AuditMetadataEntry\x12\x18\n\x10\x61\x66\x66\x65\x63ted_entries\x18\x08 \x03(\t\x12\x1b\n\x13\x63ompliance_verified\x18\t \x01(\x08\x1a\x34\n\x12\x41uditMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb6\x04\n\rTemporalLayer\x12\x10\n\x08layer_id\x18\x01 \x01(\t\x12-\n\ttimestamp\x18\x02 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x16\n\x0estate_snapshot\x18\x03 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x04 \x01(\t\x12\x12\n\ncreated_by\x18\x05 \x01(\t\x12\x12\n\nlayer_hash\x18\x06 \x01(\t\x12\x1b\n\x13previous_layer_hash\x18\x07 \x01(\t\x12\x18\n\x10rollback_allowed\x18\x08 \x01(\x08\x12\x39\n\x08segments\x18\t \x03(\x0b\x32\'.seigr.segment_metadata.SegmentMetadata\x12\x19\n\x11\x63hecksum_segments\x18\n \x03(\t\x12\x45\n\rdata_snapshot\x18\x0b \x03(\x0b\x32..seigr.lineage.TemporalLayer.DataSnapshotEntry\x12\x17\n\x0f\x62\x61\x63kup_location\x18\x0c \x01(\t\x12<\n\x08metadata\x18\r \x03(\x0b\x32*.seigr.lineage.TemporalLayer.MetadataEntry\x1a\x33\n\x11\x44\x61taSnapshotEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*C\n\x0bLineageType\x12\x0c\n\x08STANDARD\x10\x00\x12\x0c\n\x08\x42RANCHED\x10\x01\x12\n\n\x06MERGED\x10\x02\x12\x0c\n\x08\x41RCHIVED\x10\x03*\x80\x01\n\rLineageStatus\x12\x1c\n\x18LINEAGE_STATUS_UNDEFINED\x10\x00\x12\x12\n\x0eLINEAGE_ACTIVE\x10\x01\x12\x14\n\x10LINEAGE_ARCHIVED\x10\x02\x12\x12\n\x0eLINEAGE_LOCKED\x10\x03\x12\x13\n\x0fLINEAGE_RETIRED\x10\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'lineage_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_LINEAGE_METADATAENTRY']._loaded_options = None
  _globals['_LINEAGE_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_LINEAGE_ADAPTIVETRIGGERSENTRY']._loaded_options = None
  _globals['_LINEAGE_ADAPTIVETRIGGERSENTRY']._serialized_options = b'8\001'
  _globals['_LINEAGE_NETWORKPROTOCOLDATAENTRY']._loaded_options = None
  _globals['_LINEAGE_NETWORKPROTOCOLDATAENTRY']._serialized_options = b'8\001'
  _globals['_LINEAGEVALIDATIONSUMMARY_VALIDATIONMETADATAENTRY']._loaded_options = None
  _globals['_LINEAGEVALIDATIONSUMMARY_VALIDATIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_LINEAGEAUDITTRAIL_AUDITMETADATAENTRY']._loaded_options = None
  _globals['_LINEAGEAUDITTRAIL_AUDITMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_TEMPORALLAYER_DATASNAPSHOTENTRY']._loaded_options = None
  _globals['_TEMPORALLAYER_DATASNAPSHOTENTRY']._serialized_options = b'8\001'
  _globals['_TEMPORALLAYER_METADATAENTRY']._loaded_options = None
  _globals['_TEMPORALLAYER_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_LINEAGETYPE']._serialized_start=2456
  _globals['_LINEAGETYPE']._serialized_end=2523
  _globals['_LINEAGESTATUS']._serialized_start=2526
  _globals['_LINEAGESTATUS']._serialized_end=2654
  _globals['_LINEAGE']._serialized_start=104
  _globals['_LINEAGE']._serialized_end=1037
  _globals['_LINEAGE_METADATAENTRY']._serialized_start=849
  _globals['_LINEAGE_METADATAENTRY']._serialized_end=896
  _globals['_LINEAGE_ADAPTIVETRIGGERSENTRY']._serialized_start=898
  _globals['_LINEAGE_ADAPTIVETRIGGERSENTRY']._serialized_end=977
  _globals['_LINEAGE_NETWORKPROTOCOLDATAENTRY']._serialized_start=979
  _globals['_LINEAGE_NETWORKPROTOCOLDATAENTRY']._serialized_end=1037
  _globals['_LINEAGEVALIDATIONSUMMARY']._serialized_start=1040
  _globals['_LINEAGEVALIDATIONSUMMARY']._serialized_end=1515
  _globals['_LINEAGEVALIDATIONSUMMARY_VALIDATIONMETADATAENTRY']._serialized_start=1458
  _globals['_LINEAGEVALIDATIONSUMMARY_VALIDATIONMETADATAENTRY']._serialized_end=1515
  _globals['_LINEAGEAUDITTRAIL']._serialized_start=1518
  _globals['_LINEAGEAUDITTRAIL']._serialized_end=1885
  _globals['_LINEAGEAUDITTRAIL_AUDITMETADATAENTRY']._serialized_start=1833
  _globals['_LINEAGEAUDITTRAIL_AUDITMETADATAENTRY']._serialized_end=1885
  _globals['_TEMPORALLAYER']._serialized_start=1888
  _globals['_TEMPORALLAYER']._serialized_end=2454
  _globals['_TEMPORALLAYER_DATASNAPSHOTENTRY']._serialized_start=2354
  _globals['_TEMPORALLAYER_DATASNAPSHOTENTRY']._serialized_end=2405
  _globals['_TEMPORALLAYER_METADATAENTRY']._serialized_start=849
  _globals['_TEMPORALLAYER_METADATAENTRY']._serialized_end=896
# @@protoc_insertion_point(module_scope)
