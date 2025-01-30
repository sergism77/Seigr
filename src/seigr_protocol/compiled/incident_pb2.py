# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: incident.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "incident.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0eincident.proto\x12\x0eseigr.incident\x1a\x0c\x63ommon.proto"\x8d\x04\n\x0eIncidentReport\x12\x13\n\x0bincident_id\x18\x01 \x01(\t\x12\r\n\x05title\x18\x02 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12\x32\n\x08severity\x18\x04 \x01(\x0e\x32 .seigr.incident.IncidentSeverity\x12.\n\x06status\x18\x05 \x01(\x0e\x32\x1e.seigr.incident.IncidentStatus\x12\x13\n\x0breported_by\x18\x06 \x01(\t\x12,\n\x0breported_at\x18\x07 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12>\n\x08metadata\x18\x08 \x03(\x0b\x32,.seigr.incident.IncidentReport.MetadataEntry\x12\x14\n\x0cstakeholders\x18\t \x03(\t\x12-\n\x08priority\x18\n \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x12/\n\x0cthreat_level\x18\x0b \x01(\x0e\x32\x19.seigr.common.ThreatLevel\x12\x19\n\x11impacted_services\x18\x0c \x03(\t\x12\x19\n\x11related_incidents\x18\r \x03(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xa3\x03\n\x14IncidentResponsePlan\x12\x0f\n\x07plan_id\x18\x01 \x01(\t\x12\x13\n\x0bincident_id\x18\x02 \x01(\t\x12\r\n\x05steps\x18\x03 \x03(\t\x12O\n\x0e\x61ssigned_roles\x18\x04 \x03(\x0b\x32\x37.seigr.incident.IncidentResponsePlan.AssignedRolesEntry\x12+\n\ncreated_at\x18\x05 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x12\n\ncreated_by\x18\x06 \x01(\t\x12\x17\n\x0f\x61pproval_status\x18\x07 \x01(\t\x12\x44\n\x08metadata\x18\x08 \x03(\x0b\x32\x32.seigr.incident.IncidentResponsePlan.MetadataEntry\x1a\x34\n\x12\x41ssignedRolesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x99\x03\n\x12IncidentEscalation\x12\x15\n\rescalation_id\x18\x01 \x01(\t\x12\x13\n\x0bincident_id\x18\x02 \x01(\t\x12\x1a\n\x12\x65scalation_trigger\x18\x03 \x01(\t\x12\x19\n\x11\x65scalation_target\x18\x04 \x01(\t\x12*\n\ttimestamp\x18\x05 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12-\n\x08priority\x18\x06 \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x12W\n\x13\x65scalation_metadata\x18\x07 \x03(\x0b\x32:.seigr.incident.IncidentEscalation.EscalationMetadataEntry\x12\x19\n\x11\x65scalation_reason\x18\x08 \x01(\t\x12\x16\n\x0e\x61uto_escalated\x18\t \x01(\x08\x1a\x39\n\x17\x45scalationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc1\x02\n\x0bIncidentLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x13\n\x0bincident_id\x18\x02 \x01(\t\x12\x14\n\x0c\x61\x63tion_taken\x18\x03 \x01(\t\x12\x14\n\x0cperformed_by\x18\x04 \x01(\t\x12\x31\n\x10\x61\x63tion_timestamp\x18\x05 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12.\n\x06status\x18\x06 \x01(\x0e\x32\x1e.seigr.incident.IncidentStatus\x12;\n\x08metadata\x18\x07 \x03(\x0b\x32).seigr.incident.IncidentLog.MetadataEntry\x12\x10\n\x08\x63omments\x18\x08 \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xde\x02\n\x0fIncidentSummary\x12\x13\n\x0bincident_id\x18\x01 \x01(\t\x12\r\n\x05title\x18\x02 \x01(\t\x12\x32\n\x08severity\x18\x03 \x01(\x0e\x32 .seigr.incident.IncidentSeverity\x12.\n\x06status\x18\x04 \x01(\x0e\x32\x1e.seigr.incident.IncidentStatus\x12\x13\n\x0breported_by\x18\x05 \x01(\t\x12,\n\x0breported_at\x18\x06 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12,\n\x0bresolved_at\x18\x07 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x19\n\x11impacted_services\x18\x08 \x03(\t\x12\x1a\n\x12resolution_summary\x18\t \x01(\t\x12\x1b\n\x13\x65scalations_summary\x18\n \x01(\t*\x84\x01\n\x10IncidentSeverity\x12\x1f\n\x1bINCIDENT_SEVERITY_UNDEFINED\x10\x00\x12\x10\n\x0cINCIDENT_LOW\x10\x01\x12\x13\n\x0fINCIDENT_MEDIUM\x10\x02\x12\x11\n\rINCIDENT_HIGH\x10\x03\x12\x15\n\x11INCIDENT_CRITICAL\x10\x04*\xa0\x01\n\x0eIncidentStatus\x12\x1d\n\x19INCIDENT_STATUS_UNDEFINED\x10\x00\x12\x11\n\rINCIDENT_OPEN\x10\x01\x12\x18\n\x14INCIDENT_IN_PROGRESS\x10\x02\x12\x15\n\x11INCIDENT_RESOLVED\x10\x03\x12\x16\n\x12INCIDENT_ESCALATED\x10\x04\x12\x13\n\x0fINCIDENT_CLOSED\x10\x05\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "incident_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_INCIDENTREPORT_METADATAENTRY"]._loaded_options = None
    _globals["_INCIDENTREPORT_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_INCIDENTRESPONSEPLAN_ASSIGNEDROLESENTRY"]._loaded_options = None
    _globals["_INCIDENTRESPONSEPLAN_ASSIGNEDROLESENTRY"]._serialized_options = b"8\001"
    _globals["_INCIDENTRESPONSEPLAN_METADATAENTRY"]._loaded_options = None
    _globals["_INCIDENTRESPONSEPLAN_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_INCIDENTESCALATION_ESCALATIONMETADATAENTRY"]._loaded_options = None
    _globals["_INCIDENTESCALATION_ESCALATIONMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_INCIDENTLOG_METADATAENTRY"]._loaded_options = None
    _globals["_INCIDENTLOG_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_INCIDENTSEVERITY"]._serialized_start = 2088
    _globals["_INCIDENTSEVERITY"]._serialized_end = 2220
    _globals["_INCIDENTSTATUS"]._serialized_start = 2223
    _globals["_INCIDENTSTATUS"]._serialized_end = 2383
    _globals["_INCIDENTREPORT"]._serialized_start = 49
    _globals["_INCIDENTREPORT"]._serialized_end = 574
    _globals["_INCIDENTREPORT_METADATAENTRY"]._serialized_start = 527
    _globals["_INCIDENTREPORT_METADATAENTRY"]._serialized_end = 574
    _globals["_INCIDENTRESPONSEPLAN"]._serialized_start = 577
    _globals["_INCIDENTRESPONSEPLAN"]._serialized_end = 996
    _globals["_INCIDENTRESPONSEPLAN_ASSIGNEDROLESENTRY"]._serialized_start = 895
    _globals["_INCIDENTRESPONSEPLAN_ASSIGNEDROLESENTRY"]._serialized_end = 947
    _globals["_INCIDENTRESPONSEPLAN_METADATAENTRY"]._serialized_start = 527
    _globals["_INCIDENTRESPONSEPLAN_METADATAENTRY"]._serialized_end = 574
    _globals["_INCIDENTESCALATION"]._serialized_start = 999
    _globals["_INCIDENTESCALATION"]._serialized_end = 1408
    _globals["_INCIDENTESCALATION_ESCALATIONMETADATAENTRY"]._serialized_start = 1351
    _globals["_INCIDENTESCALATION_ESCALATIONMETADATAENTRY"]._serialized_end = 1408
    _globals["_INCIDENTLOG"]._serialized_start = 1411
    _globals["_INCIDENTLOG"]._serialized_end = 1732
    _globals["_INCIDENTLOG_METADATAENTRY"]._serialized_start = 527
    _globals["_INCIDENTLOG_METADATAENTRY"]._serialized_end = 574
    _globals["_INCIDENTSUMMARY"]._serialized_start = 1735
    _globals["_INCIDENTSUMMARY"]._serialized_end = 2085
# @@protoc_insertion_point(module_scope)
