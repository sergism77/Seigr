# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: documentation.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "documentation.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import audit_pb2 as audit__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x13\x64ocumentation.proto\x12\x13seigr.documentation\x1a\x0b\x61udit.proto"\xd4\x03\n\x08\x44ocument\x12\x13\n\x0b\x64ocument_id\x18\x01 \x01(\t\x12\r\n\x05title\x18\x02 \x01(\t\x12/\n\x04type\x18\x03 \x01(\x0e\x32!.seigr.documentation.DocumentType\x12\x38\n\x06status\x18\x04 \x01(\x0e\x32(.seigr.documentation.DocumentationStatus\x12\x0f\n\x07\x63ontent\x18\x05 \x01(\t\x12\x0e\n\x06\x61uthor\x18\x06 \x01(\t\x12\x12\n\ncreated_at\x18\x07 \x01(\t\x12\x12\n\nupdated_at\x18\x08 \x01(\t\x12=\n\x08metadata\x18\t \x03(\x0b\x32+.seigr.documentation.Document.MetadataEntry\x12\x15\n\rcollaborators\x18\n \x03(\t\x12\x1e\n\x16\x63ompliance_requirement\x18\x0b \x01(\t\x12\x1b\n\x13\x61\x63\x63\x65ss_control_list\x18\x0c \x03(\t\x12\x0f\n\x07version\x18\r \x01(\t\x12\x1b\n\x13previous_version_id\x18\x0e \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xcb\x02\n\x12KnowledgeBaseEntry\x12\x10\n\x08\x65ntry_id\x18\x01 \x01(\t\x12\x10\n\x08question\x18\x02 \x01(\t\x12\x0e\n\x06\x61nswer\x18\x03 \x01(\t\x12\x12\n\ncreated_by\x18\x04 \x01(\t\x12\x12\n\ncreated_at\x18\x05 \x01(\t\x12G\n\x08metadata\x18\x06 \x03(\x0b\x32\x35.seigr.documentation.KnowledgeBaseEntry.MetadataEntry\x12\x17\n\x0frelated_entries\x18\x07 \x03(\t\x12\x38\n\x06status\x18\x08 \x01(\x0e\x32(.seigr.documentation.DocumentationStatus\x12\x0c\n\x04tags\x18\t \x03(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc8\x02\n\x07Runbook\x12\x12\n\nrunbook_id\x18\x01 \x01(\t\x12\r\n\x05title\x18\x02 \x01(\t\x12\x38\n\x06status\x18\x03 \x01(\x0e\x32(.seigr.documentation.DocumentationStatus\x12/\n\x05steps\x18\x04 \x03(\x0b\x32 .seigr.documentation.RunbookStep\x12\x12\n\ncreated_by\x18\x05 \x01(\t\x12\x12\n\ncreated_at\x18\x06 \x01(\t\x12<\n\x08metadata\x18\x07 \x03(\x0b\x32*.seigr.documentation.Runbook.MetadataEntry\x12\x18\n\x10\x61\x63\x63\x65ss_policy_id\x18\x08 \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xbf\x01\n\x0bRunbookStep\x12\x0f\n\x07step_id\x18\x01 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x02 \x01(\t\x12;\n\x0b\x61\x63tion_type\x18\x03 \x01(\x0e\x32&.seigr.documentation.RunbookActionType\x12\x16\n\x0e\x61\x63tion_details\x18\x04 \x01(\t\x12\x1a\n\x12\x64\x65pendency_step_id\x18\x05 \x01(\t\x12\x19\n\x11requires_approval\x18\x06 \x01(\x08"\x8a\x01\n\x17\x44ocumentationAuditTrail\x12.\n\raudit_entries\x18\x01 \x03(\x0b\x32\x17.seigr.audit.AuditEntry\x12\x13\n\x0b\x64ocument_id\x18\x02 \x01(\t\x12\x14\n\x0cgenerated_at\x18\x03 \x01(\t\x12\x14\n\x0cgenerated_by\x18\x04 \x01(\t*\x7f\n\x13\x44ocumentationStatus\x12\x14\n\x10STATUS_UNDEFINED\x10\x00\x12\x10\n\x0cSTATUS_DRAFT\x10\x01\x12\x14\n\x10STATUS_PUBLISHED\x10\x02\x12\x13\n\x0fSTATUS_ARCHIVED\x10\x03\x12\x15\n\x11STATUS_DEPRECATED\x10\x04*\x92\x01\n\x0c\x44ocumentType\x12\x1b\n\x17\x44OCUMENT_TYPE_UNDEFINED\x10\x00\x12\x17\n\x13\x44OCUMENT_TYPE_GUIDE\x10\x01\x12\x18\n\x14\x44OCUMENT_TYPE_POLICY\x10\x02\x12\x1b\n\x17\x44OCUMENT_TYPE_REFERENCE\x10\x03\x12\x15\n\x11\x44OCUMENT_TYPE_FAQ\x10\x04*\x87\x01\n\x11RunbookActionType\x12\x1c\n\x18RUNBOOK_ACTION_UNDEFINED\x10\x00\x12\x19\n\x15RUNBOOK_ACTION_MANUAL\x10\x01\x12\x1c\n\x18RUNBOOK_ACTION_AUTOMATED\x10\x02\x12\x1b\n\x17RUNBOOK_ACTION_APPROVAL\x10\x03\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "documentation_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_DOCUMENT_METADATAENTRY"]._loaded_options = None
    _globals["_DOCUMENT_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_KNOWLEDGEBASEENTRY_METADATAENTRY"]._loaded_options = None
    _globals["_KNOWLEDGEBASEENTRY_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_RUNBOOK_METADATAENTRY"]._loaded_options = None
    _globals["_RUNBOOK_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_DOCUMENTATIONSTATUS"]._serialized_start = 1528
    _globals["_DOCUMENTATIONSTATUS"]._serialized_end = 1655
    _globals["_DOCUMENTTYPE"]._serialized_start = 1658
    _globals["_DOCUMENTTYPE"]._serialized_end = 1804
    _globals["_RUNBOOKACTIONTYPE"]._serialized_start = 1807
    _globals["_RUNBOOKACTIONTYPE"]._serialized_end = 1942
    _globals["_DOCUMENT"]._serialized_start = 58
    _globals["_DOCUMENT"]._serialized_end = 526
    _globals["_DOCUMENT_METADATAENTRY"]._serialized_start = 479
    _globals["_DOCUMENT_METADATAENTRY"]._serialized_end = 526
    _globals["_KNOWLEDGEBASEENTRY"]._serialized_start = 529
    _globals["_KNOWLEDGEBASEENTRY"]._serialized_end = 860
    _globals["_KNOWLEDGEBASEENTRY_METADATAENTRY"]._serialized_start = 479
    _globals["_KNOWLEDGEBASEENTRY_METADATAENTRY"]._serialized_end = 526
    _globals["_RUNBOOK"]._serialized_start = 863
    _globals["_RUNBOOK"]._serialized_end = 1191
    _globals["_RUNBOOK_METADATAENTRY"]._serialized_start = 479
    _globals["_RUNBOOK_METADATAENTRY"]._serialized_end = 526
    _globals["_RUNBOOKSTEP"]._serialized_start = 1194
    _globals["_RUNBOOKSTEP"]._serialized_end = 1385
    _globals["_DOCUMENTATIONAUDITTRAIL"]._serialized_start = 1388
    _globals["_DOCUMENTATIONAUDITTRAIL"]._serialized_end = 1526
# @@protoc_insertion_point(module_scope)
