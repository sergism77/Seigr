# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: src/dot_seigr/seigr_protocol/seed_dot_seigr.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n1src/dot_seigr/seigr_protocol/seed_dot_seigr.proto\x12\x05seigr\"\xe5\x02\n\x0cSeedDotSeigr\x12\x11\n\troot_hash\x18\x01 \x01(\t\x12\x11\n\tseed_hash\x18\x02 \x01(\t\x12\x1a\n\x12\x63reation_timestamp\x18\x03 \x01(\t\x12(\n\x08segments\x18\x04 \x03(\x0b\x32\x16.seigr.SegmentMetadata\x12\x1a\n\x12secondary_clusters\x18\x05 \x03(\t\x12,\n\x0fnetwork_lineage\x18\x06 \x03(\x0b\x32\x13.seigr.LineageEntry\x12 \n\x18secondary_cluster_active\x18\x07 \x01(\x08\x12\x0f\n\x07version\x18\x08 \x01(\t\x12*\n\rfile_metadata\x18\t \x01(\x0b\x32\x13.seigr.FileMetadata\x12-\n\x0ftemporal_layers\x18\n \x03(\x0b\x32\x14.seigr.TemporalLayer\x12\x11\n\tlast_ping\x18\x0b \x01(\x03\"\xdf\x01\n\x0c\x46ileMetadata\x12\x0f\n\x07version\x18\x01 \x01(\t\x12\x12\n\ncreator_id\x18\x02 \x01(\t\x12\x19\n\x11original_filename\x18\x03 \x01(\t\x12\x1a\n\x12original_extension\x18\x04 \x01(\t\x12\x11\n\tfile_hash\x18\x05 \x01(\t\x12\x1a\n\x12\x63reation_timestamp\x18\x06 \x01(\t\x12\x16\n\x0etotal_segments\x18\x07 \x01(\x05\x12,\n\x0e\x61\x63\x63\x65ss_context\x18\x08 \x01(\x0b\x32\x14.seigr.AccessContext\"\x80\x02\n\x0fSegmentMetadata\x12\x0f\n\x07version\x18\x01 \x01(\t\x12\x12\n\ncreator_id\x18\x02 \x01(\t\x12\x15\n\rsegment_index\x18\x03 \x01(\x05\x12\x14\n\x0csegment_hash\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12\x14\n\x0cprimary_link\x18\x06 \x01(\t\x12\x17\n\x0fsecondary_links\x18\x07 \x03(\t\x12\x30\n\x10\x63oordinate_index\x18\x08 \x01(\x0b\x32\x16.seigr.CoordinateIndex\x12\x11\n\tdata_hash\x18\t \x01(\t\x12\x14\n\x0cthreat_level\x18\n \x01(\x05\"\xd4\x01\n\rTemporalLayer\x12\x11\n\ttimestamp\x18\x01 \x01(\t\x12(\n\x08segments\x18\x02 \x03(\x0b\x32\x16.seigr.SegmentMetadata\x12\x12\n\nlayer_hash\x18\x03 \x01(\t\x12=\n\rdata_snapshot\x18\x04 \x03(\x0b\x32&.seigr.TemporalLayer.DataSnapshotEntry\x1a\x33\n\x11\x44\x61taSnapshotEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\"3\n\x0cLineageEntry\x12\x10\n\x08seigr_id\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\t\"2\n\x0f\x43oordinateIndex\x12\t\n\x01x\x18\x01 \x01(\x05\x12\t\n\x01y\x18\x02 \x01(\x05\x12\t\n\x01z\x18\x03 \x01(\x05\"Y\n\rAccessContext\x12\x14\n\x0c\x61\x63\x63\x65ss_count\x18\x01 \x01(\x05\x12\x15\n\rlast_accessed\x18\x02 \x01(\t\x12\x1b\n\x13node_access_history\x18\x03 \x03(\tb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'src.dot_seigr.seigr_protocol.seed_dot_seigr_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _TEMPORALLAYER_DATASNAPSHOTENTRY._options = None
  _TEMPORALLAYER_DATASNAPSHOTENTRY._serialized_options = b'8\001'
  _SEEDDOTSEIGR._serialized_start=61
  _SEEDDOTSEIGR._serialized_end=418
  _FILEMETADATA._serialized_start=421
  _FILEMETADATA._serialized_end=644
  _SEGMENTMETADATA._serialized_start=647
  _SEGMENTMETADATA._serialized_end=903
  _TEMPORALLAYER._serialized_start=906
  _TEMPORALLAYER._serialized_end=1118
  _TEMPORALLAYER_DATASNAPSHOTENTRY._serialized_start=1067
  _TEMPORALLAYER_DATASNAPSHOTENTRY._serialized_end=1118
  _LINEAGEENTRY._serialized_start=1120
  _LINEAGEENTRY._serialized_end=1171
  _COORDINATEINDEX._serialized_start=1173
  _COORDINATEINDEX._serialized_end=1223
  _ACCESSCONTEXT._serialized_start=1225
  _ACCESSCONTEXT._serialized_end=1314
# @@protoc_insertion_point(module_scope)
