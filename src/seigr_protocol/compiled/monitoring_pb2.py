# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: monitoring.proto
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
    'monitoring.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10monitoring.proto\x12\x05seigr\x1a\x0c\x63ommon.proto\"\xe5\x04\n\nEscalation\x12\x15\n\rescalation_id\x18\x01 \x01(\t\x12\x14\n\x0csegment_hash\x18\x02 \x01(\t\x12(\n\x0cthreat_level\x18\x03 \x01(\x0e\x32\x12.seigr.ThreatLevel\x12.\n\x0f\x65scalation_type\x18\x04 \x01(\x0e\x32\x15.seigr.EscalationType\x12\x14\n\x0c\x65scalated_at\x18\x05 \x01(\t\x12\x1d\n\x15replication_triggered\x18\x06 \x01(\x08\x12\x19\n\x11\x65scalation_reason\x18\x07 \x01(\t\x12\x18\n\x10\x61lert_recipients\x18\x08 \x03(\t\x12\x31\n\x08metadata\x18\t \x03(\x0b\x32\x1f.seigr.Escalation.MetadataEntry\x12\x17\n\x0fresponse_status\x18\n \x01(\t\x12\x14\n\x0cresponder_id\x18\x0b \x01(\t\x12\x1c\n\x14resolution_timestamp\x18\x0c \x01(\t\x12\x18\n\x10response_details\x18\r \x01(\t\x12\x1d\n\x15next_review_timestamp\x18\x0e \x01(\t\x12\x34\n\x12\x65scalation_history\x18\x0f \x03(\x0b\x32\x18.seigr.EscalationHistory\x12\"\n\x1a\x63ritical_protocol_override\x18\x10 \x01(\x08\x12\"\n\x1auser_intervention_required\x18\x11 \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb0\x02\n\x11\x45scalationHistory\x12\x11\n\tupdate_id\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\t\x12\x0e\n\x06status\x18\x03 \x01(\t\x12\x14\n\x0c\x61\x63tion_taken\x18\x04 \x01(\t\x12\x12\n\nupdated_by\x18\x05 \x01(\t\x12\x45\n\x0f\x61\x64\x64itional_info\x18\x06 \x03(\x0b\x32,.seigr.EscalationHistory.AdditionalInfoEntry\x12\x1c\n\x14\x61\x64\x61ptive_action_flag\x18\x07 \x01(\x08\x12\x1f\n\x17threat_escalation_score\x18\x08 \x01(\x02\x1a\x35\n\x13\x41\x64\x64itionalInfoEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xaf\x05\n\x10MonitoringConfig\x12\x1a\n\x12\x63ritical_threshold\x18\x01 \x01(\x05\x12\x18\n\x10severe_threshold\x18\x02 \x01(\x05\x12\x1a\n\x12moderate_threshold\x18\x03 \x01(\x05\x12\'\n\x1f\x61\x64\x61ptive_check_interval_seconds\x18\x04 \x01(\x05\x12\x1f\n\x17\x61lert_frequency_minutes\x18\x05 \x01(\x05\x12\x1c\n\x14\x65nable_auto_lockdown\x18\x06 \x01(\x08\x12\x44\n\x0f\x63onfig_metadata\x18\x07 \x03(\x0b\x32+.seigr.MonitoringConfig.ConfigMetadataEntry\x12\x16\n\x0e\x63onfig_version\x18\x08 \x01(\t\x12\x14\n\x0clast_updated\x18\t \x01(\t\x12\x1f\n\x17\x65nable_severity_scaling\x18\n \x01(\x08\x12!\n\x19\x64\x65\x66\x61ult_response_strategy\x18\x0b \x01(\t\x12\x1d\n\x15\x64ynamic_alert_scaling\x18\x0c \x01(\x08\x12\x19\n\x11\x66\x61llback_strategy\x18\r \x01(\t\x12\x1d\n\x15\x64\x61ta_volume_threshold\x18\x0e \x01(\x05\x12*\n\"high_frequency_monitoring_interval\x18\x0f \x01(\x05\x12%\n\x1d\x61\x64\x61ptive_threshold_adjustment\x18\x10 \x01(\x02\x12\"\n\x1a\x65nable_centralized_logging\x18\x11 \x01(\x08\x12\"\n\x1aprioritize_high_risk_zones\x18\x12 \x01(\x08\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc5\x05\n\x15\x41\x64\x61ptiveMonitoringLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x19\n\x11monitored_segment\x18\x02 \x01(\t\x12\x31\n\x15\x64\x65tected_threat_level\x18\x03 \x01(\x0e\x32\x12.seigr.ThreatLevel\x12\x17\n\x0f\x63heck_timestamp\x18\x04 \x01(\t\x12\x1c\n\x14triggered_escalation\x18\x05 \x01(\x08\x12\x15\n\rescalation_id\x18\x06 \x01(\t\x12\x43\n\x0clog_metadata\x18\x07 \x03(\x0b\x32-.seigr.AdaptiveMonitoringLog.LogMetadataEntry\x12\x1d\n\x15response_action_taken\x18\x08 \x01(\t\x12\x1c\n\x14next_check_scheduled\x18\t \x01(\t\x12\x1a\n\x12\x64\x65tection_accuracy\x18\n \x01(\x02\x12\x1b\n\x13monitoring_operator\x18\x0b \x01(\t\x12Q\n\x13\x61\x64\x61ptive_parameters\x18\x0c \x03(\x0b\x32\x34.seigr.AdaptiveMonitoringLog.AdaptiveParametersEntry\x12$\n\x1c\x65scalation_probability_score\x18\r \x01(\x02\x12!\n\x19protocol_adjustment_notes\x18\x0e \x01(\t\x12\x16\n\x0e\x64\x61ta_source_id\x18\x0f \x01(\t\x12\"\n\x1aproactive_response_enabled\x18\x10 \x01(\x08\x1a\x32\n\x10LogMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x39\n\x17\x41\x64\x61ptiveParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe9\x05\n\x16MonitoringCycleSummary\x12\x12\n\nsummary_id\x18\x01 \x01(\t\x12\x17\n\x0f\x63ycle_timestamp\x18\x02 \x01(\t\x12\x1e\n\x16total_checks_conducted\x18\x03 \x01(\x05\x12\x1d\n\x15\x65scalations_triggered\x18\x04 \x01(\x05\x12\x1b\n\x13\x63ritical_detections\x18\x05 \x01(\x05\x12\"\n\x1a\x61verage_detection_accuracy\x18\x06 \x01(\x02\x12\x1c\n\x14highlighted_segments\x18\x07 \x03(\t\x12H\n\x0e\x63ycle_metadata\x18\x08 \x03(\x0b\x32\x30.seigr.MonitoringCycleSummary.CycleMetadataEntry\x12\x1c\n\x14next_cycle_scheduled\x18\t \x01(\t\x12!\n\x19\x61\x64\x61ptive_measures_applied\x18\n \x01(\x08\x12P\n\x12\x65scalation_summary\x18\x0b \x03(\x0b\x32\x34.seigr.MonitoringCycleSummary.EscalationSummaryEntry\x12[\n\x18\x64\x65tection_trend_analysis\x18\x0c \x03(\x0b\x32\x39.seigr.MonitoringCycleSummary.DetectionTrendAnalysisEntry\x12\x1b\n\x13\x63ycle_summary_notes\x18\r \x01(\t\x1a\x34\n\x12\x43ycleMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x38\n\x16\x45scalationSummaryEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a=\n\x1b\x44\x65tectionTrendAnalysisEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x02:\x02\x38\x01*\xf5\x01\n\x0e\x45scalationType\x12\x1d\n\x19\x45SCALATION_TYPE_UNDEFINED\x10\x00\x12&\n\"ESCALATION_TYPE_THREAT_REPLICATION\x10\x01\x12\x1e\n\x1a\x45SCALATION_TYPE_ALERT_ONLY\x10\x02\x12#\n\x1f\x45SCALATION_TYPE_SYSTEM_LOCKDOWN\x10\x03\x12,\n(ESCALATION_TYPE_ADAPTIVE_RECONFIGURATION\x10\x04\x12)\n%ESCALATION_TYPE_USER_ALERT_ESCALATION\x10\x05\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'monitoring_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_ESCALATION_METADATAENTRY']._loaded_options = None
  _globals['_ESCALATION_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ESCALATIONHISTORY_ADDITIONALINFOENTRY']._loaded_options = None
  _globals['_ESCALATIONHISTORY_ADDITIONALINFOENTRY']._serialized_options = b'8\001'
  _globals['_MONITORINGCONFIG_CONFIGMETADATAENTRY']._loaded_options = None
  _globals['_MONITORINGCONFIG_CONFIGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY']._loaded_options = None
  _globals['_ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY']._loaded_options = None
  _globals['_ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_MONITORINGCYCLESUMMARY_CYCLEMETADATAENTRY']._loaded_options = None
  _globals['_MONITORINGCYCLESUMMARY_CYCLEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MONITORINGCYCLESUMMARY_ESCALATIONSUMMARYENTRY']._loaded_options = None
  _globals['_MONITORINGCYCLESUMMARY_ESCALATIONSUMMARYENTRY']._serialized_options = b'8\001'
  _globals['_MONITORINGCYCLESUMMARY_DETECTIONTRENDANALYSISENTRY']._loaded_options = None
  _globals['_MONITORINGCYCLESUMMARY_DETECTIONTRENDANALYSISENTRY']._serialized_options = b'8\001'
  _globals['_ESCALATIONTYPE']._serialized_start=3115
  _globals['_ESCALATIONTYPE']._serialized_end=3360
  _globals['_ESCALATION']._serialized_start=42
  _globals['_ESCALATION']._serialized_end=655
  _globals['_ESCALATION_METADATAENTRY']._serialized_start=608
  _globals['_ESCALATION_METADATAENTRY']._serialized_end=655
  _globals['_ESCALATIONHISTORY']._serialized_start=658
  _globals['_ESCALATIONHISTORY']._serialized_end=962
  _globals['_ESCALATIONHISTORY_ADDITIONALINFOENTRY']._serialized_start=909
  _globals['_ESCALATIONHISTORY_ADDITIONALINFOENTRY']._serialized_end=962
  _globals['_MONITORINGCONFIG']._serialized_start=965
  _globals['_MONITORINGCONFIG']._serialized_end=1652
  _globals['_MONITORINGCONFIG_CONFIGMETADATAENTRY']._serialized_start=1599
  _globals['_MONITORINGCONFIG_CONFIGMETADATAENTRY']._serialized_end=1652
  _globals['_ADAPTIVEMONITORINGLOG']._serialized_start=1655
  _globals['_ADAPTIVEMONITORINGLOG']._serialized_end=2364
  _globals['_ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY']._serialized_start=2255
  _globals['_ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY']._serialized_end=2305
  _globals['_ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY']._serialized_start=2307
  _globals['_ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY']._serialized_end=2364
  _globals['_MONITORINGCYCLESUMMARY']._serialized_start=2367
  _globals['_MONITORINGCYCLESUMMARY']._serialized_end=3112
  _globals['_MONITORINGCYCLESUMMARY_CYCLEMETADATAENTRY']._serialized_start=2939
  _globals['_MONITORINGCYCLESUMMARY_CYCLEMETADATAENTRY']._serialized_end=2991
  _globals['_MONITORINGCYCLESUMMARY_ESCALATIONSUMMARYENTRY']._serialized_start=2993
  _globals['_MONITORINGCYCLESUMMARY_ESCALATIONSUMMARYENTRY']._serialized_end=3049
  _globals['_MONITORINGCYCLESUMMARY_DETECTIONTRENDANALYSISENTRY']._serialized_start=3051
  _globals['_MONITORINGCYCLESUMMARY_DETECTIONTRENDANALYSISENTRY']._serialized_end=3112
# @@protoc_insertion_point(module_scope)
