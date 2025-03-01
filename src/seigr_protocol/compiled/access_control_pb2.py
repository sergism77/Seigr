# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: access_control.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "access_control.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x14\x61\x63\x63\x65ss_control.proto\x12\x14seigr.access_control\x1a\x1fgoogle/protobuf/timestamp.proto"[\n\rAccessContext\x12\x14\n\x0c\x61\x63\x63\x65ss_count\x18\x01 \x01(\x05\x12\x15\n\rlast_accessed\x18\x02 \x01(\t\x12\x1d\n\x15hyphen_access_history\x18\x03 \x03(\t"\xb2\x02\n\x04Role\x12\x0f\n\x07role_id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x39\n\x0bpermissions\x18\x03 \x03(\x0e\x32$.seigr.access_control.PermissionType\x12@\n\x0b\x63onstraints\x18\x04 \x03(\x0b\x32+.seigr.access_control.Role.ConstraintsEntry\x12\x14\n\x0c\x63\x61n_delegate\x18\x05 \x01(\x08\x12\x19\n\x11inheritance_depth\x18\x06 \x01(\x05\x12\x14\n\x0cparent_roles\x18\x07 \x03(\t\x12\x13\n\x0b\x64\x65scription\x18\x08 \x01(\t\x1a\x32\n\x10\x43onstraintsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xea\x02\n\nPermission\x12\x11\n\tentity_id\x18\x01 \x01(\t\x12,\n\x04role\x18\x02 \x01(\x0e\x32\x1e.seigr.access_control.RoleType\x12\x35\n\x07\x61\x63tions\x18\x03 \x03(\x0e\x32$.seigr.access_control.PermissionType\x12\x13\n\x0b\x63onstraints\x18\x04 \x01(\t\x12*\n\x06\x65xpiry\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x14\n\x0crequires_mfa\x18\x06 \x01(\x08\x12@\n\x08metadata\x18\x07 \x03(\x0b\x32..seigr.access_control.Permission.MetadataEntry\x12\x1a\n\x12\x63onditional_access\x18\x08 \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x94\x04\n\x12\x41\x63\x63\x65ssControlEntry\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12,\n\x04role\x18\x02 \x01(\x0e\x32\x1e.seigr.access_control.RoleType\x12\x39\n\x0bpermissions\x18\x03 \x03(\x0e\x32$.seigr.access_control.PermissionType\x12\x39\n\x0f\x61llowed_actions\x18\x04 \x03(\x0e\x32 .seigr.access_control.AccessType\x12\x14\n\x0cis_inherited\x18\x05 \x01(\x08\x12\x32\n\x0e\x65\x66\x66\x65\x63tive_from\x18\x06 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12.\n\nexpires_on\x18\x07 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x14\n\x0cmfa_required\x18\x08 \x01(\x08\x12\x14\n\x0c\x64\x65legated_by\x18\t \x01(\t\x12\x15\n\raccess_reason\x18\n \x01(\t\x12U\n\x0f\x63ustom_metadata\x18\x0b \x03(\x0b\x32<.seigr.access_control.AccessControlEntry.CustomMetadataEntry\x1a\x35\n\x13\x43ustomMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x88\x03\n\x11\x41\x63\x63\x65ssControlList\x12\x39\n\x07\x65ntries\x18\x01 \x03(\x0b\x32(.seigr.access_control.AccessControlEntry\x12\x0f\n\x07version\x18\x02 \x01(\t\x12G\n\x08metadata\x18\x03 \x03(\x0b\x32\x35.seigr.access_control.AccessControlList.MetadataEntry\x12\x11\n\tpolicy_id\x18\x04 \x01(\t\x12\x32\n\x06status\x18\x05 \x01(\x0e\x32".seigr.access_control.PolicyStatus\x12\x31\n\rlast_reviewed\x18\x06 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x33\n\x0fnext_review_due\x18\x07 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xf1\x03\n\x0c\x41\x63\x63\x65ssPolicy\x12\x11\n\tpolicy_id\x18\x01 \x01(\t\x12\x13\n\x0bpolicy_name\x18\x02 \x01(\t\x12\x32\n\x06status\x18\x03 \x01(\x0e\x32".seigr.access_control.PolicyStatus\x12\x36\n\x12\x63reation_timestamp\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x35\n\x11updated_timestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x35\n\x0bpermissions\x18\x06 \x03(\x0b\x32 .seigr.access_control.Permission\x12/\n\x0b\x65nforced_on\x18\x07 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x42\n\x08metadata\x18\x08 \x03(\x0b\x32\x30.seigr.access_control.AccessPolicy.MetadataEntry\x12\x18\n\x10\x61pplicable_roles\x18\t \x03(\t\x12\x1f\n\x17\x63ompliance_requirements\x18\n \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xaf\x03\n\x0e\x41\x63\x63\x65ssAuditLog\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12\x30\n\x06\x61\x63tion\x18\x02 \x01(\x0e\x32 .seigr.access_control.AccessType\x12-\n\ttimestamp\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x0e\n\x06status\x18\x04 \x01(\t\x12\x0f\n\x07\x64\x65tails\x18\x05 \x01(\t\x12\x12\n\nip_address\x18\x06 \x01(\t\x12\x13\n\x0b\x64\x65vice_info\x18\x07 \x01(\t\x12\x14\n\x0cmfa_verified\x18\x08 \x01(\x08\x12\x18\n\x10\x64\x65legated_access\x18\t \x01(\x08\x12\x13\n\x0borigin_role\x18\n \x01(\t\x12\x15\n\raccess_reason\x18\x0b \x01(\t\x12O\n\x0e\x61udit_metadata\x18\x0c \x03(\x0b\x32\x37.seigr.access_control.AccessAuditLog.AuditMetadataEntry\x1a\x34\n\x12\x41uditMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xd8\x01\n\x08RoleType\x12\x17\n\x13ROLE_TYPE_UNDEFINED\x10\x00\x12\x13\n\x0fROLE_TYPE_ADMIN\x10\x01\x12\x14\n\x10ROLE_TYPE_EDITOR\x10\x02\x12\x14\n\x10ROLE_TYPE_VIEWER\x10\x03\x12\x19\n\x15ROLE_TYPE_CONTRIBUTOR\x10\x04\x12\x15\n\x11ROLE_TYPE_AUDITOR\x10\x05\x12\x17\n\x13ROLE_TYPE_DELEGATOR\x10\x06\x12\x11\n\rROLE_TYPE_API\x10\x07\x12\x14\n\x10ROLE_TYPE_SYSTEM\x10\x08*\xa9\x02\n\x0ePermissionType\x12\x1d\n\x19PERMISSION_TYPE_UNDEFINED\x10\x00\x12\x18\n\x14PERMISSION_TYPE_READ\x10\x01\x12\x19\n\x15PERMISSION_TYPE_WRITE\x10\x02\x12\x1b\n\x17PERMISSION_TYPE_EXECUTE\x10\x03\x12\x1a\n\x16PERMISSION_TYPE_DELETE\x10\x04\x12\x19\n\x15PERMISSION_TYPE_SHARE\x10\x05\x12\x1a\n\x16PERMISSION_TYPE_MANAGE\x10\x06\x12\x1c\n\x18PERMISSION_TYPE_DELEGATE\x10\x07\x12\x19\n\x15PERMISSION_TYPE_AUDIT\x10\x08\x12\x1a\n\x16PERMISSION_TYPE_BYPASS\x10\t*\xee\x01\n\nAccessType\x12\x19\n\x15\x41\x43\x43\x45SS_TYPE_UNDEFINED\x10\x00\x12\x14\n\x10\x41\x43\x43\x45SS_TYPE_READ\x10\x01\x12\x15\n\x11\x41\x43\x43\x45SS_TYPE_WRITE\x10\x02\x12\x17\n\x13\x41\x43\x43\x45SS_TYPE_EXECUTE\x10\x03\x12\x16\n\x12\x41\x43\x43\x45SS_TYPE_DELETE\x10\x04\x12\x15\n\x11\x41\x43\x43\x45SS_TYPE_SHARE\x10\x05\x12\x1c\n\x18\x41\x43\x43\x45SS_TYPE_ADMINISTRATE\x10\x06\x12\x18\n\x14\x41\x43\x43\x45SS_TYPE_DELEGATE\x10\x07\x12\x18\n\x14\x41\x43\x43\x45SS_TYPE_API_CALL\x10\x08*\xdd\x01\n\x0cPolicyStatus\x12\x1b\n\x17POLICY_STATUS_UNDEFINED\x10\x00\x12\x18\n\x14POLICY_STATUS_ACTIVE\x10\x01\x12\x1a\n\x16POLICY_STATUS_INACTIVE\x10\x02\x12\x19\n\x15POLICY_STATUS_EXPIRED\x10\x03\x12\x19\n\x15POLICY_STATUS_REVOKED\x10\x04\x12 \n\x1cPOLICY_STATUS_PENDING_REVIEW\x10\x05\x12"\n\x1ePOLICY_STATUS_SCHEDULED_REVIEW\x10\x06*\xa6\x01\n\x12\x41\x63\x63\x65ssDecisionType\x12\x1d\n\x19\x41\x43\x43\x45SS_DECISION_UNDEFINED\x10\x00\x12\x19\n\x15\x41\x43\x43\x45SS_DECISION_ALLOW\x10\x01\x12\x18\n\x14\x41\x43\x43\x45SS_DECISION_DENY\x10\x02\x12\x1f\n\x1b\x41\x43\x43\x45SS_DECISION_CONDITIONAL\x10\x03\x12\x1b\n\x17\x41\x43\x43\x45SS_DECISION_PENDING\x10\x04\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "access_control_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_ROLE_CONSTRAINTSENTRY"]._loaded_options = None
    _globals["_ROLE_CONSTRAINTSENTRY"]._serialized_options = b"8\001"
    _globals["_PERMISSION_METADATAENTRY"]._loaded_options = None
    _globals["_PERMISSION_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ACCESSCONTROLENTRY_CUSTOMMETADATAENTRY"]._loaded_options = None
    _globals["_ACCESSCONTROLENTRY_CUSTOMMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ACCESSCONTROLLIST_METADATAENTRY"]._loaded_options = None
    _globals["_ACCESSCONTROLLIST_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ACCESSPOLICY_METADATAENTRY"]._loaded_options = None
    _globals["_ACCESSPOLICY_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ACCESSAUDITLOG_AUDITMETADATAENTRY"]._loaded_options = None
    _globals["_ACCESSAUDITLOG_AUDITMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ROLETYPE"]._serialized_start = 2711
    _globals["_ROLETYPE"]._serialized_end = 2927
    _globals["_PERMISSIONTYPE"]._serialized_start = 2930
    _globals["_PERMISSIONTYPE"]._serialized_end = 3227
    _globals["_ACCESSTYPE"]._serialized_start = 3230
    _globals["_ACCESSTYPE"]._serialized_end = 3468
    _globals["_POLICYSTATUS"]._serialized_start = 3471
    _globals["_POLICYSTATUS"]._serialized_end = 3692
    _globals["_ACCESSDECISIONTYPE"]._serialized_start = 3695
    _globals["_ACCESSDECISIONTYPE"]._serialized_end = 3861
    _globals["_ACCESSCONTEXT"]._serialized_start = 79
    _globals["_ACCESSCONTEXT"]._serialized_end = 170
    _globals["_ROLE"]._serialized_start = 173
    _globals["_ROLE"]._serialized_end = 479
    _globals["_ROLE_CONSTRAINTSENTRY"]._serialized_start = 429
    _globals["_ROLE_CONSTRAINTSENTRY"]._serialized_end = 479
    _globals["_PERMISSION"]._serialized_start = 482
    _globals["_PERMISSION"]._serialized_end = 844
    _globals["_PERMISSION_METADATAENTRY"]._serialized_start = 797
    _globals["_PERMISSION_METADATAENTRY"]._serialized_end = 844
    _globals["_ACCESSCONTROLENTRY"]._serialized_start = 847
    _globals["_ACCESSCONTROLENTRY"]._serialized_end = 1379
    _globals["_ACCESSCONTROLENTRY_CUSTOMMETADATAENTRY"]._serialized_start = 1326
    _globals["_ACCESSCONTROLENTRY_CUSTOMMETADATAENTRY"]._serialized_end = 1379
    _globals["_ACCESSCONTROLLIST"]._serialized_start = 1382
    _globals["_ACCESSCONTROLLIST"]._serialized_end = 1774
    _globals["_ACCESSCONTROLLIST_METADATAENTRY"]._serialized_start = 797
    _globals["_ACCESSCONTROLLIST_METADATAENTRY"]._serialized_end = 844
    _globals["_ACCESSPOLICY"]._serialized_start = 1777
    _globals["_ACCESSPOLICY"]._serialized_end = 2274
    _globals["_ACCESSPOLICY_METADATAENTRY"]._serialized_start = 797
    _globals["_ACCESSPOLICY_METADATAENTRY"]._serialized_end = 844
    _globals["_ACCESSAUDITLOG"]._serialized_start = 2277
    _globals["_ACCESSAUDITLOG"]._serialized_end = 2708
    _globals["_ACCESSAUDITLOG_AUDITMETADATAENTRY"]._serialized_start = 2656
    _globals["_ACCESSAUDITLOG_AUDITMETADATAENTRY"]._serialized_end = 2708
# @@protoc_insertion_point(module_scope)
