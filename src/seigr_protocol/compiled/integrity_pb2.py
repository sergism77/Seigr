# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: integrity.proto
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
    'integrity.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import segment_metadata_pb2 as segment__metadata__pb2
import encryption_pb2 as encryption__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0fintegrity.proto\x12\x05seigr\x1a\x16segment_metadata.proto\x1a\x10\x65ncryption.proto\"\xe3\x04\n\x15MonitoringCycleResult\x12\x10\n\x08\x63ycle_id\x18\x01 \x01(\t\x12-\n\x0fsegments_status\x18\x02 \x03(\x0b\x32\x14.seigr.SegmentStatus\x12\x14\n\x0c\x63ompleted_at\x18\x03 \x01(\t\x12\x1e\n\x16total_threats_detected\x18\x04 \x01(\x05\x12\x1c\n\x14new_threats_detected\x18\x05 \x01(\x05\x12I\n\x0f\x61\x64\x64itional_info\x18\x06 \x03(\x0b\x32\x30.seigr.MonitoringCycleResult.AdditionalInfoEntry\x12\x16\n\x0e\x63ycle_duration\x18\x07 \x01(\t\x12\x14\n\x0cinitiated_by\x18\x08 \x01(\t\x12\x30\n\x11threat_severities\x18\t \x03(\x0e\x32\x15.seigr.ThreatSeverity\x12\x19\n\x11resolution_status\x18\n \x01(\t\x12G\n\x0ethreat_summary\x18\x0b \x03(\x0b\x32/.seigr.MonitoringCycleResult.ThreatSummaryEntry\x12\x1c\n\x14next_cycle_scheduled\x18\x0c \x01(\t\x12\x1b\n\x13impacted_components\x18\r \x03(\t\x1a\x35\n\x13\x41\x64\x64itionalInfoEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x34\n\x12ThreatSummaryEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\"\x99\t\n\x14ThreatAnalysisReport\x12\x11\n\treport_id\x18\x01 \x01(\t\x12\x34\n\x0bthreat_logs\x18\x02 \x03(\x0b\x32\x1f.seigr.IntegrityVerificationLog\x12\x1e\n\x16total_critical_threats\x18\x03 \x01(\x05\x12\x1a\n\x12total_high_threats\x18\x04 \x01(\x05\x12\x1e\n\x16total_moderate_threats\x18\x05 \x01(\x05\x12\x19\n\x11total_low_threats\x18\x06 \x01(\x05\x12\x1a\n\x12\x61nalysis_timestamp\x18\x07 \x01(\t\x12P\n\x13recommended_actions\x18\x08 \x03(\x0b\x32\x33.seigr.ThreatAnalysisReport.RecommendedActionsEntry\x12;\n\x08metadata\x18\t \x03(\x0b\x32).seigr.ThreatAnalysisReport.MetadataEntry\x12H\n\x0f\x61\x63tion_priority\x18\n \x03(\x0b\x32/.seigr.ThreatAnalysisReport.ActionPriorityEntry\x12\x15\n\rreport_author\x18\x0b \x01(\t\x12\x17\n\x0freport_duration\x18\x0c \x01(\t\x12L\n\x11threat_recurrence\x18\r \x03(\x0b\x32\x31.seigr.ThreatAnalysisReport.ThreatRecurrenceEntry\x12\x17\n\x0f\x65scalation_path\x18\x0e \x03(\t\x12\x1a\n\x12unresolved_threats\x18\x0f \x03(\t\x12L\n\x11\x61\x64\x61ptive_response\x18\x10 \x03(\x0b\x32\x31.seigr.ThreatAnalysisReport.AdaptiveResponseEntry\x12\x1f\n\x17next_analysis_scheduled\x18\x11 \x01(\t\x12W\n\x17\x63omponent_threat_counts\x18\x12 \x03(\x0b\x32\x36.seigr.ThreatAnalysisReport.ComponentThreatCountsEntry\x1a\x39\n\x17RecommendedActionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x35\n\x13\x41\x63tionPriorityEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x37\n\x15ThreatRecurrenceEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x37\n\x15\x41\x64\x61ptiveResponseEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a<\n\x1a\x43omponentThreatCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01*\x9e\x01\n\x0eThreatSeverity\x12\x1d\n\x19THREAT_SEVERITY_UNDEFINED\x10\x00\x12\x17\n\x13THREAT_SEVERITY_LOW\x10\x01\x12\x1c\n\x18THREAT_SEVERITY_MODERATE\x10\x02\x12\x18\n\x14THREAT_SEVERITY_HIGH\x10\x03\x12\x1c\n\x18THREAT_SEVERITY_CRITICAL\x10\x04\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'integrity_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_MONITORINGCYCLERESULT_ADDITIONALINFOENTRY']._loaded_options = None
  _globals['_MONITORINGCYCLERESULT_ADDITIONALINFOENTRY']._serialized_options = b'8\001'
  _globals['_MONITORINGCYCLERESULT_THREATSUMMARYENTRY']._loaded_options = None
  _globals['_MONITORINGCYCLERESULT_THREATSUMMARYENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_RECOMMENDEDACTIONSENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_RECOMMENDEDACTIONSENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_METADATAENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_ACTIONPRIORITYENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_ACTIONPRIORITYENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_THREATRECURRENCEENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_THREATRECURRENCEENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_ADAPTIVERESPONSEENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_ADAPTIVERESPONSEENTRY']._serialized_options = b'8\001'
  _globals['_THREATANALYSISREPORT_COMPONENTTHREATCOUNTSENTRY']._loaded_options = None
  _globals['_THREATANALYSISREPORT_COMPONENTTHREATCOUNTSENTRY']._serialized_options = b'8\001'
  _globals['_THREATSEVERITY']._serialized_start=1863
  _globals['_THREATSEVERITY']._serialized_end=2021
  _globals['_MONITORINGCYCLERESULT']._serialized_start=69
  _globals['_MONITORINGCYCLERESULT']._serialized_end=680
  _globals['_MONITORINGCYCLERESULT_ADDITIONALINFOENTRY']._serialized_start=573
  _globals['_MONITORINGCYCLERESULT_ADDITIONALINFOENTRY']._serialized_end=626
  _globals['_MONITORINGCYCLERESULT_THREATSUMMARYENTRY']._serialized_start=628
  _globals['_MONITORINGCYCLERESULT_THREATSUMMARYENTRY']._serialized_end=680
  _globals['_THREATANALYSISREPORT']._serialized_start=683
  _globals['_THREATANALYSISREPORT']._serialized_end=1860
  _globals['_THREATANALYSISREPORT_RECOMMENDEDACTIONSENTRY']._serialized_start=1523
  _globals['_THREATANALYSISREPORT_RECOMMENDEDACTIONSENTRY']._serialized_end=1580
  _globals['_THREATANALYSISREPORT_METADATAENTRY']._serialized_start=1582
  _globals['_THREATANALYSISREPORT_METADATAENTRY']._serialized_end=1629
  _globals['_THREATANALYSISREPORT_ACTIONPRIORITYENTRY']._serialized_start=1631
  _globals['_THREATANALYSISREPORT_ACTIONPRIORITYENTRY']._serialized_end=1684
  _globals['_THREATANALYSISREPORT_THREATRECURRENCEENTRY']._serialized_start=1686
  _globals['_THREATANALYSISREPORT_THREATRECURRENCEENTRY']._serialized_end=1741
  _globals['_THREATANALYSISREPORT_ADAPTIVERESPONSEENTRY']._serialized_start=1743
  _globals['_THREATANALYSISREPORT_ADAPTIVERESPONSEENTRY']._serialized_end=1798
  _globals['_THREATANALYSISREPORT_COMPONENTTHREATCOUNTSENTRY']._serialized_start=1800
  _globals['_THREATANALYSISREPORT_COMPONENTTHREATCOUNTSENTRY']._serialized_end=1860
# @@protoc_insertion_point(module_scope)
