# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: lineage.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rlineage.proto\x12\x05seigr\"\xa2\x05\n\x07Lineage\x12\x12\n\nlineage_id\x18\x01 \x01(\t\x12\x12\n\ncreator_id\x18\x02 \x01(\t\x12\x14\n\x0c\x63urrent_hash\x18\x03 \x01(\t\x12\x16\n\x0e\x66ormat_version\x18\x04 \x01(\t\x12(\n\x0clineage_type\x18\x05 \x01(\x0e\x32\x12.seigr.LineageType\x12$\n\x06status\x18\x06 \x01(\x0e\x32\x14.seigr.LineageStatus\x12$\n\x07\x65ntries\x18\x07 \x03(\x0b\x32\x13.seigr.LineageEntry\x12\x1a\n\x12integrity_checksum\x18\x08 \x01(\t\x12.\n\x08metadata\x18\t \x03(\x0b\x32\x1c.seigr.Lineage.MetadataEntry\x12\x19\n\x11parent_lineage_id\x18\n \x01(\t\x12\x19\n\x11\x61rchive_timestamp\x18\x0b \x01(\t\x12\x18\n\x10\x61ssociated_files\x18\x0c \x03(\t\x12\x1c\n\x14network_reference_id\x18\r \x01(\t\x12\x1a\n\x12\x61\x63\x63\x65ss_permissions\x18\x0e \x03(\t\x12\x17\n\x0flinked_lineages\x18\x0f \x03(\t\x12\x15\n\rlast_modified\x18\x10 \x01(\t\x12?\n\x11\x61\x64\x61ptive_triggers\x18\x11 \x03(\x0b\x32$.seigr.Lineage.AdaptiveTriggersEntry\x12\x1a\n\x12\x64\x65precation_policy\x18\x12 \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x37\n\x15\x41\x64\x61ptiveTriggersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xcb\x06\n\x0cLineageEntry\x12\x10\n\x08\x65ntry_id\x18\x01 \x01(\t\x12\x15\n\rentry_version\x18\x02 \x01(\t\x12$\n\nentry_type\x18\x03 \x01(\x0e\x32\x10.seigr.EntryType\x12\x0e\n\x06\x61\x63tion\x18\x04 \x01(\t\x12\x12\n\ncreator_id\x18\x05 \x01(\t\x12\x16\n\x0e\x63ontributor_id\x18\x06 \x01(\t\x12\x11\n\ttimestamp\x18\x07 \x01(\t\x12\x17\n\x0fprevious_hashes\x18\x08 \x03(\t\x12\x11\n\tparent_id\x18\t \x01(\t\x12\x15\n\revent_trigger\x18\n \x01(\t\x12\x33\n\x08metadata\x18\x0b \x03(\x0b\x32!.seigr.LineageEntry.MetadataEntry\x12\x16\n\x0e\x65ntry_checksum\x18\x0c \x01(\t\x12\x1d\n\x15\x65xternal_reference_id\x18\r \x01(\t\x12\x16\n\x0e\x64\x65pendency_ids\x18\x0e \x03(\t\x12:\n\x0c\x63ontext_data\x18\x0f \x03(\x0b\x32$.seigr.LineageEntry.ContextDataEntry\x12\x18\n\x10\x61ssociated_files\x18\x10 \x03(\t\x12\x1c\n\x14\x61\x64\x61ptive_update_flag\x18\x11 \x01(\x08\x12$\n\x1c\x63onflict_resolution_strategy\x18\x12 \x01(\t\x12\x1d\n\x15resolved_dependencies\x18\x13 \x03(\t\x12\x16\n\x0erevision_notes\x18\x14 \x01(\t\x12H\n\x13\x61\x64\x61ptive_conditions\x18\x15 \x03(\x0b\x32+.seigr.LineageEntry.AdaptiveConditionsEntry\x12\x1b\n\x13rollback_checkpoint\x18\x16 \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x32\n\x10\x43ontextDataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x39\n\x17\x41\x64\x61ptiveConditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*C\n\x0bLineageType\x12\x0c\n\x08STANDARD\x10\x00\x12\x0c\n\x08\x42RANCHED\x10\x01\x12\n\n\x06MERGED\x10\x02\x12\x0c\n\x08\x41RCHIVED\x10\x03*~\n\tEntryType\x12\x0c\n\x08\x43REATION\x10\x00\x12\x10\n\x0cMODIFICATION\x10\x01\x12\t\n\x05MERGE\x10\x02\x12\x0c\n\x08\x44\x45LETION\x10\x03\x12\x08\n\x04\x46ORK\x10\x04\x12\x0b\n\x07RESTORE\x10\x05\x12\x0c\n\x08SNAPSHOT\x10\x06\x12\x13\n\x0f\x41\x44\x41PTIVE_UPDATE\x10\x07*\x80\x01\n\rLineageStatus\x12\x1c\n\x18LINEAGE_STATUS_UNDEFINED\x10\x00\x12\x12\n\x0eLINEAGE_ACTIVE\x10\x01\x12\x14\n\x10LINEAGE_ARCHIVED\x10\x02\x12\x12\n\x0eLINEAGE_LOCKED\x10\x03\x12\x13\n\x0fLINEAGE_RETIRED\x10\x04\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'lineage_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _LINEAGE_METADATAENTRY._options = None
  _LINEAGE_METADATAENTRY._serialized_options = b'8\001'
  _LINEAGE_ADAPTIVETRIGGERSENTRY._options = None
  _LINEAGE_ADAPTIVETRIGGERSENTRY._serialized_options = b'8\001'
  _LINEAGEENTRY_METADATAENTRY._options = None
  _LINEAGEENTRY_METADATAENTRY._serialized_options = b'8\001'
  _LINEAGEENTRY_CONTEXTDATAENTRY._options = None
  _LINEAGEENTRY_CONTEXTDATAENTRY._serialized_options = b'8\001'
  _LINEAGEENTRY_ADAPTIVECONDITIONSENTRY._options = None
  _LINEAGEENTRY_ADAPTIVECONDITIONSENTRY._serialized_options = b'8\001'
  _LINEAGETYPE._serialized_start=1547
  _LINEAGETYPE._serialized_end=1614
  _ENTRYTYPE._serialized_start=1616
  _ENTRYTYPE._serialized_end=1742
  _LINEAGESTATUS._serialized_start=1745
  _LINEAGESTATUS._serialized_end=1873
  _LINEAGE._serialized_start=25
  _LINEAGE._serialized_end=699
  _LINEAGE_METADATAENTRY._serialized_start=595
  _LINEAGE_METADATAENTRY._serialized_end=642
  _LINEAGE_ADAPTIVETRIGGERSENTRY._serialized_start=644
  _LINEAGE_ADAPTIVETRIGGERSENTRY._serialized_end=699
  _LINEAGEENTRY._serialized_start=702
  _LINEAGEENTRY._serialized_end=1545
  _LINEAGEENTRY_METADATAENTRY._serialized_start=595
  _LINEAGEENTRY_METADATAENTRY._serialized_end=642
  _LINEAGEENTRY_CONTEXTDATAENTRY._serialized_start=1436
  _LINEAGEENTRY_CONTEXTDATAENTRY._serialized_end=1486
  _LINEAGEENTRY_ADAPTIVECONDITIONSENTRY._serialized_start=1488
  _LINEAGEENTRY_ADAPTIVECONDITIONSENTRY._serialized_end=1545
# @@protoc_insertion_point(module_scope)
