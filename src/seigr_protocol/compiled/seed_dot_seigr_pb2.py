# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: seed_dot_seigr.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import file_metadata_pb2 as file__metadata__pb2
import segment_metadata_pb2 as segment__metadata__pb2
import lineage_pb2 as lineage__pb2
import pipeline_pb2 as pipeline__pb2
import access_control_pb2 as access__control__pb2
import replication_pb2 as replication__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x14seed_dot_seigr.proto\x12\x05seigr\x1a\x13\x66ile_metadata.proto\x1a\x16segment_metadata.proto\x1a\rlineage.proto\x1a\x0epipeline.proto\x1a\x14\x61\x63\x63\x65ss_control.proto\x1a\x11replication.proto\"\xa7\x07\n\x0cSeedDotSeigr\x12\x11\n\troot_hash\x18\x01 \x01(\t\x12\x11\n\tseed_hash\x18\x02 \x01(\t\x12\x1a\n\x12\x63reation_timestamp\x18\x03 \x01(\t\x12(\n\x08segments\x18\x04 \x03(\x0b\x32\x16.seigr.SegmentMetadata\x12\x1a\n\x12\x63onnected_clusters\x18\x05 \x03(\t\x12,\n\x0flineage_entries\x18\x06 \x03(\x0b\x32\x13.seigr.LineageEntry\x12\x1b\n\x13is_secondary_active\x18\x07 \x01(\x08\x12\x0f\n\x07version\x18\x08 \x01(\t\x12*\n\rfile_metadata\x18\t \x01(\x0b\x32\x13.seigr.FileMetadata\x12-\n\x0ftemporal_layers\x18\n \x03(\x0b\x32\x14.seigr.TemporalLayer\x12\x11\n\tlast_ping\x18\x0b \x01(\x03\x12%\n\x03\x61\x63l\x18\x0c \x01(\x0b\x32\x18.seigr.AccessControlList\x12\x1a\n\x12integrity_checksum\x18\r \x01(\t\x12-\n\x0fpipeline_stages\x18\x0e \x03(\x0b\x32\x14.seigr.PipelineStage\x12+\n\x0eoperation_logs\x18\x0f \x03(\x0b\x32\x13.seigr.OperationLog\x12\x18\n\x10integrity_status\x18\x10 \x01(\t\x12\x15\n\rlast_verified\x18\x11 \x01(\t\x12\x37\n\x11integrity_history\x18\x12 \x03(\x0b\x32\x1c.seigr.IntegrityVerification\x12\x38\n\x0b\x63ustom_data\x18\x13 \x03(\x0b\x32#.seigr.SeedDotSeigr.CustomDataEntry\x12\x34\n\x12replication_status\x18\x14 \x01(\x0b\x32\x18.seigr.ReplicationStatus\x12\x33\n\x15\x63ompatibility_history\x18\x15 \x03(\x0b\x32\x14.seigr.Compatibility\x12\x33\n\x08metadata\x18\x16 \x03(\x0b\x32!.seigr.SeedDotSeigr.MetadataEntry\x1a\x31\n\x0f\x43ustomDataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x86\x02\n\x15IntegrityVerification\x12\x0e\n\x06status\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\t\x12\x13\n\x0bverifier_id\x18\x03 \x01(\t\x12:\n\x07\x64\x65tails\x18\x04 \x03(\x0b\x32).seigr.IntegrityVerification.DetailsEntry\x12\x17\n\x0fintegrity_level\x18\x05 \x01(\t\x12\x15\n\rerror_message\x18\x06 \x01(\t\x12\x19\n\x11integrity_context\x18\x07 \x01(\t\x1a.\n\x0c\x44\x65tailsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xbc\x03\n\rCompatibility\x12\x16\n\x0etarget_version\x18\x01 \x01(\t\x12\x18\n\x10migration_status\x18\x02 \x01(\t\x12I\n\x13\x63ompatibility_notes\x18\x03 \x03(\x0b\x32,.seigr.Compatibility.CompatibilityNotesEntry\x12\x13\n\x0blast_tested\x18\x04 \x01(\t\x12\x1b\n\x13\x61\x66\x66\x65\x63ted_components\x18\x05 \x03(\t\x12G\n\x12migration_metadata\x18\x06 \x03(\x0b\x32+.seigr.Compatibility.MigrationMetadataEntry\x12\x1a\n\x12migration_strategy\x18\x07 \x01(\t\x12\"\n\x1a\x61\x64\x61ptive_migration_enabled\x18\x08 \x01(\x08\x1a\x39\n\x17\x43ompatibilityNotesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x38\n\x16MigrationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'seed_dot_seigr_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _SEEDDOTSEIGR_CUSTOMDATAENTRY._options = None
  _SEEDDOTSEIGR_CUSTOMDATAENTRY._serialized_options = b'8\001'
  _SEEDDOTSEIGR_METADATAENTRY._options = None
  _SEEDDOTSEIGR_METADATAENTRY._serialized_options = b'8\001'
  _INTEGRITYVERIFICATION_DETAILSENTRY._options = None
  _INTEGRITYVERIFICATION_DETAILSENTRY._serialized_options = b'8\001'
  _COMPATIBILITY_COMPATIBILITYNOTESENTRY._options = None
  _COMPATIBILITY_COMPATIBILITYNOTESENTRY._serialized_options = b'8\001'
  _COMPATIBILITY_MIGRATIONMETADATAENTRY._options = None
  _COMPATIBILITY_MIGRATIONMETADATAENTRY._serialized_options = b'8\001'
  _SEEDDOTSEIGR._serialized_start=149
  _SEEDDOTSEIGR._serialized_end=1084
  _SEEDDOTSEIGR_CUSTOMDATAENTRY._serialized_start=986
  _SEEDDOTSEIGR_CUSTOMDATAENTRY._serialized_end=1035
  _SEEDDOTSEIGR_METADATAENTRY._serialized_start=1037
  _SEEDDOTSEIGR_METADATAENTRY._serialized_end=1084
  _INTEGRITYVERIFICATION._serialized_start=1087
  _INTEGRITYVERIFICATION._serialized_end=1349
  _INTEGRITYVERIFICATION_DETAILSENTRY._serialized_start=1303
  _INTEGRITYVERIFICATION_DETAILSENTRY._serialized_end=1349
  _COMPATIBILITY._serialized_start=1352
  _COMPATIBILITY._serialized_end=1796
  _COMPATIBILITY_COMPATIBILITYNOTESENTRY._serialized_start=1681
  _COMPATIBILITY_COMPATIBILITYNOTESENTRY._serialized_end=1738
  _COMPATIBILITY_MIGRATIONMETADATAENTRY._serialized_start=1740
  _COMPATIBILITY_MIGRATIONMETADATAENTRY._serialized_end=1796
# @@protoc_insertion_point(module_scope)
