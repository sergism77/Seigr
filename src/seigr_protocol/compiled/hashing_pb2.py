# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: hashing.proto
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
    'hashing.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rhashing.proto\x12\x05seigr\"\xc2\x05\n\x08HashData\x12\x0f\n\x07hash_id\x18\x01 \x01(\t\x12\'\n\talgorithm\x18\x02 \x01(\x0e\x32\x14.seigr.HashAlgorithm\x12\x15\n\rdata_snapshot\x18\x03 \x01(\x0c\x12\x0c\n\x04salt\x18\x04 \x01(\t\x12\x12\n\nhash_value\x18\x05 \x01(\t\x12\x19\n\x11\x61lgorithm_version\x18\x06 \x01(\x05\x12\x16\n\x0esenary_encoded\x18\x07 \x01(\x08\x12\x1a\n\x12\x63reation_timestamp\x18\x08 \x01(\t\x12\x12\n\ntrace_code\x18\t \x01(\t\x12\x36\n\x13verification_status\x18\n \x01(\x0e\x32\x19.seigr.VerificationStatus\x12\x15\n\rprevious_hash\x18\x0b \x01(\t\x12\x15\n\rlinked_hashes\x18\x0c \x03(\t\x12\x44\n\x13\x61\x64\x61ptive_parameters\x18\r \x03(\x0b\x32\'.seigr.HashData.AdaptiveParametersEntry\x12\x16\n\x0esenary_version\x18\x0e \x01(\x05\x12/\n\x08metadata\x18\x0f \x03(\x0b\x32\x1d.seigr.HashData.MetadataEntry\x12\x17\n\x0fhash_expiration\x18\x10 \x01(\t\x12\x15\n\rentropy_level\x18\x11 \x01(\x02\x12\x17\n\x0fhash_adaptation\x18\x12 \x01(\t\x12\x17\n\x0f\x65ntropy_sources\x18\x13 \x03(\t\x12\x1d\n\x15origin_data_reference\x18\x14 \x01(\t\x1a\x39\n\x17\x41\x64\x61ptiveParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf3\x04\n\x08HashTree\x12\x0f\n\x07tree_id\x18\x01 \x01(\t\x12$\n\x0broot_hashes\x18\x02 \x03(\x0b\x32\x0f.seigr.HashData\x12+\n\x06layers\x18\x03 \x03(\x0b\x32\x1b.seigr.HashTree.LayersEntry\x12\r\n\x05\x64\x65pth\x18\x04 \x01(\x05\x12\x1a\n\x12\x63reation_timestamp\x18\x05 \x01(\t\x12\x33\n\x10integrity_status\x18\x06 \x01(\x0e\x32\x19.seigr.VerificationStatus\x12/\n\x08metadata\x18\x07 \x03(\x0b\x32\x1d.seigr.HashTree.MetadataEntry\x12\x1f\n\x17last_verified_timestamp\x18\x08 \x01(\t\x12\x1b\n\x13integrity_threshold\x18\t \x01(\x02\x12\x19\n\x11\x64\x65pendency_hashes\x18\n \x03(\t\x12\x1d\n\x15root_confidence_level\x18\x0b \x01(\x02\x12K\n\x17layer_confidence_levels\x18\x0c \x03(\x0b\x32*.seigr.HashTree.LayerConfidenceLevelsEntry\x1a>\n\x0bLayersEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\x1e\n\x05value\x18\x02 \x01(\x0b\x32\x0f.seigr.HashData:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a<\n\x1aLayerConfidenceLevelsEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x02:\x02\x38\x01\"\x80\x04\n\x0fVerificationLog\x12\x17\n\x0fverification_id\x18\x01 \x01(\t\x12\x16\n\x0etarget_hash_id\x18\x02 \x01(\t\x12)\n\x06status\x18\x03 \x01(\x0e\x32\x19.seigr.VerificationStatus\x12\x13\n\x0bverifier_id\x18\x04 \x01(\t\x12\x1e\n\x16verification_timestamp\x18\x05 \x01(\t\x12\x15\n\rerror_message\x18\x06 \x01(\t\x12\x16\n\x0everified_depth\x18\x07 \x01(\x05\x12O\n\x15verification_metadata\x18\x08 \x03(\x0b\x32\x30.seigr.VerificationLog.VerificationMetadataEntry\x12\x16\n\x0e\x61lgorithm_used\x18\t \x01(\t\x12\x1f\n\x17verification_confidence\x18\n \x01(\x02\x12\x13\n\x0b\x61udit_trail\x18\x0b \x03(\t\x12\x1a\n\x12verification_notes\x18\x0c \x01(\t\x12\x16\n\x0eretry_attempts\x18\r \x01(\x05\x12\x1d\n\x15verification_duration\x18\x0e \x01(\t\x1a;\n\x19VerificationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\x9c\x01\n\rHashAlgorithm\x12\x1c\n\x18HASH_ALGORITHM_UNDEFINED\x10\x00\x12\x0f\n\x0bHASH_SHA256\x10\x01\x12\x0f\n\x0bHASH_SHA512\x10\x02\x12\x10\n\x0cHASH_BLAKE2B\x10\x03\x12\x15\n\x11HASH_SEIGR_SENARY\x10\x04\x12\x11\n\rHASH_SHA3_256\x10\x05\x12\x0f\n\x0bHASH_ARGON2\x10\x06*\xb8\x01\n\x12VerificationStatus\x12!\n\x1dVERIFICATION_STATUS_UNDEFINED\x10\x00\x12\x0c\n\x08VERIFIED\x10\x01\x12\x0e\n\nUNVERIFIED\x10\x02\x12\x14\n\x10HASH_COMPROMISED\x10\x03\x12\x18\n\x14VERIFICATION_PENDING\x10\x04\x12\x16\n\x12PARTIALLY_VERIFIED\x10\x05\x12\x19\n\x15REQUIRES_REVALIDATION\x10\x06\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'hashing_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_HASHDATA_ADAPTIVEPARAMETERSENTRY']._loaded_options = None
  _globals['_HASHDATA_ADAPTIVEPARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_HASHDATA_METADATAENTRY']._loaded_options = None
  _globals['_HASHDATA_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_HASHTREE_LAYERSENTRY']._loaded_options = None
  _globals['_HASHTREE_LAYERSENTRY']._serialized_options = b'8\001'
  _globals['_HASHTREE_METADATAENTRY']._loaded_options = None
  _globals['_HASHTREE_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_HASHTREE_LAYERCONFIDENCELEVELSENTRY']._loaded_options = None
  _globals['_HASHTREE_LAYERCONFIDENCELEVELSENTRY']._serialized_options = b'8\001'
  _globals['_VERIFICATIONLOG_VERIFICATIONMETADATAENTRY']._loaded_options = None
  _globals['_VERIFICATIONLOG_VERIFICATIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_HASHALGORITHM']._serialized_start=1879
  _globals['_HASHALGORITHM']._serialized_end=2035
  _globals['_VERIFICATIONSTATUS']._serialized_start=2038
  _globals['_VERIFICATIONSTATUS']._serialized_end=2222
  _globals['_HASHDATA']._serialized_start=25
  _globals['_HASHDATA']._serialized_end=731
  _globals['_HASHDATA_ADAPTIVEPARAMETERSENTRY']._serialized_start=625
  _globals['_HASHDATA_ADAPTIVEPARAMETERSENTRY']._serialized_end=682
  _globals['_HASHDATA_METADATAENTRY']._serialized_start=684
  _globals['_HASHDATA_METADATAENTRY']._serialized_end=731
  _globals['_HASHTREE']._serialized_start=734
  _globals['_HASHTREE']._serialized_end=1361
  _globals['_HASHTREE_LAYERSENTRY']._serialized_start=1188
  _globals['_HASHTREE_LAYERSENTRY']._serialized_end=1250
  _globals['_HASHTREE_METADATAENTRY']._serialized_start=684
  _globals['_HASHTREE_METADATAENTRY']._serialized_end=731
  _globals['_HASHTREE_LAYERCONFIDENCELEVELSENTRY']._serialized_start=1301
  _globals['_HASHTREE_LAYERCONFIDENCELEVELSENTRY']._serialized_end=1361
  _globals['_VERIFICATIONLOG']._serialized_start=1364
  _globals['_VERIFICATIONLOG']._serialized_end=1876
  _globals['_VERIFICATIONLOG_VERIFICATIONMETADATAENTRY']._serialized_start=1817
  _globals['_VERIFICATIONLOG_VERIFICATIONMETADATAENTRY']._serialized_end=1876
# @@protoc_insertion_point(module_scope)
