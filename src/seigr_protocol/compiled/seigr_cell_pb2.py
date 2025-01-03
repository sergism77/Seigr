# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: seigr_cell.proto
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
    'seigr_cell.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10seigr_cell.proto\x12\nseigr_cell\"\xab\x02\n\tSeigrCell\x12\x14\n\x0c\x64\x61ta_content\x18\x01 \x01(\x0c\x12!\n\x19primary_redundancy_marker\x18\x02 \x01(\x0c\x12#\n\x1bsecondary_redundancy_marker\x18\x03 \x01(\x0c\x12&\n\x08metadata\x18\x04 \x01(\x0b\x32\x14.seigr_cell.Metadata\x12\x35\n\x10\x63oordinate_index\x18\x05 \x01(\x0b\x32\x1b.seigr_cell.CoordinateIndex\x12*\n\nre_license\x18\x06 \x01(\x0b\x32\x16.seigr_cell.RE_License\x12\x35\n\x11\x63ustom_properties\x18\x07 \x03(\x0b\x32\x1a.seigr_cell.CustomProperty\"\xec\x01\n\x08Metadata\x12\x0f\n\x07\x63\x65ll_id\x18\x01 \x01(\t\x12\x16\n\x0e\x63ontributor_id\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x0f\n\x07version\x18\x04 \x01(\t\x12\x11\n\thash_link\x18\x05 \x01(\t\x12\x11\n\tdata_hash\x18\x06 \x01(\t\x12\x14\n\x0clineage_hash\x18\x07 \x01(\t\x12\x14\n\x0c\x61\x63\x63\x65ss_level\x18\x08 \x01(\t\x12\x0c\n\x04tags\x18\t \x03(\t\x12\x1d\n\x15\x63ompression_algorithm\x18\n \x01(\t\x12\x14\n\x0cis_encrypted\x18\x0b \x01(\x08\"=\n\x0f\x43oordinateIndex\x12\t\n\x01x\x18\x01 \x01(\x05\x12\t\n\x01y\x18\x02 \x01(\x05\x12\t\n\x01z\x18\x03 \x01(\x05\x12\t\n\x01t\x18\x04 \x01(\t\"\xa8\x01\n\nRE_License\x12\x14\n\x0clicense_type\x18\x01 \x01(\t\x12\r\n\x05terms\x18\x02 \x01(\t\x12\x12\n\nlicense_id\x18\x03 \x01(\t\x12\x14\n\x0c\x63ontributors\x18\x04 \x03(\t\x12\x1d\n\x15\x65thical_use_guideline\x18\x05 \x01(\t\x12,\n\x0bpermissions\x18\x06 \x01(\x0b\x32\x17.seigr_cell.Permissions\"\xa0\x01\n\x0bPermissions\x12\x1a\n\x12\x61llow_modification\x18\x01 \x01(\x08\x12\x19\n\x11\x61llow_derivatives\x18\x02 \x01(\x08\x12\x1c\n\x14\x61llow_commercial_use\x18\x03 \x01(\x08\x12\x1e\n\x16geographic_restriction\x18\x04 \x01(\t\x12\x1c\n\x14temporal_restriction\x18\x05 \x01(\t\",\n\x0e\x43ustomProperty\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\tb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'seigr_cell_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_SEIGRCELL']._serialized_start=33
  _globals['_SEIGRCELL']._serialized_end=332
  _globals['_METADATA']._serialized_start=335
  _globals['_METADATA']._serialized_end=571
  _globals['_COORDINATEINDEX']._serialized_start=573
  _globals['_COORDINATEINDEX']._serialized_end=634
  _globals['_RE_LICENSE']._serialized_start=637
  _globals['_RE_LICENSE']._serialized_end=805
  _globals['_PERMISSIONS']._serialized_start=808
  _globals['_PERMISSIONS']._serialized_end=968
  _globals['_CUSTOMPROPERTY']._serialized_start=970
  _globals['_CUSTOMPROPERTY']._serialized_end=1014
# @@protoc_insertion_point(module_scope)
