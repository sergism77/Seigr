# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: monitoring.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10monitoring.proto\x12\x05seigr\x1a\x0c\x63ommon.proto\"\x9d\x04\n\nEscalation\x12\x15\n\rescalation_id\x18\x01 \x01(\t\x12\x14\n\x0csegment_hash\x18\x02 \x01(\t\x12(\n\x0cthreat_level\x18\x03 \x01(\x0e\x32\x12.seigr.ThreatLevel\x12.\n\x0f\x65scalation_type\x18\x04 \x01(\x0e\x32\x15.seigr.EscalationType\x12\x14\n\x0c\x65scalated_at\x18\x05 \x01(\t\x12\x1d\n\x15replication_triggered\x18\x06 \x01(\x08\x12\x19\n\x11\x65scalation_reason\x18\x07 \x01(\t\x12\x18\n\x10\x61lert_recipients\x18\x08 \x03(\t\x12\x31\n\x08metadata\x18\t \x03(\x0b\x32\x1f.seigr.Escalation.MetadataEntry\x12\x17\n\x0fresponse_status\x18\n \x01(\t\x12\x14\n\x0cresponder_id\x18\x0b \x01(\t\x12\x1c\n\x14resolution_timestamp\x18\x0c \x01(\t\x12\x18\n\x10response_details\x18\r \x01(\t\x12\x1d\n\x15next_review_timestamp\x18\x0e \x01(\t\x12\x34\n\x12\x65scalation_history\x18\x0f \x03(\x0b\x32\x18.seigr.EscalationHistory\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf1\x01\n\x11\x45scalationHistory\x12\x11\n\tupdate_id\x18\x01 \x01(\t\x12\x11\n\ttimestamp\x18\x02 \x01(\t\x12\x0e\n\x06status\x18\x03 \x01(\t\x12\x14\n\x0c\x61\x63tion_taken\x18\x04 \x01(\t\x12\x12\n\nupdated_by\x18\x05 \x01(\t\x12\x45\n\x0f\x61\x64\x64itional_info\x18\x06 \x03(\x0b\x32,.seigr.EscalationHistory.AdditionalInfoEntry\x1a\x35\n\x13\x41\x64\x64itionalInfoEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x8c\x04\n\x10MonitoringConfig\x12\x1a\n\x12\x63ritical_threshold\x18\x01 \x01(\x05\x12\x18\n\x10severe_threshold\x18\x02 \x01(\x05\x12\x1a\n\x12moderate_threshold\x18\x03 \x01(\x05\x12\x1f\n\x17\x61\x64\x61ptive_check_interval\x18\x04 \x01(\x05\x12\x1f\n\x17\x61lert_frequency_minutes\x18\x05 \x01(\x05\x12\x1c\n\x14\x65nable_auto_lockdown\x18\x06 \x01(\x08\x12\x44\n\x0f\x63onfig_metadata\x18\x07 \x03(\x0b\x32+.seigr.MonitoringConfig.ConfigMetadataEntry\x12\x16\n\x0e\x63onfig_version\x18\x08 \x01(\t\x12\x14\n\x0clast_updated\x18\t \x01(\t\x12\x1f\n\x17\x65nable_severity_scaling\x18\n \x01(\x08\x12!\n\x19\x64\x65\x66\x61ult_response_strategy\x18\x0b \x01(\t\x12\x1d\n\x15\x64ynamic_alert_scaling\x18\x0c \x01(\x08\x12\x19\n\x11\x66\x61llback_strategy\x18\r \x01(\t\x12\x1d\n\x15\x64\x61ta_volume_threshold\x18\x0e \x01(\x05\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc0\x04\n\x15\x41\x64\x61ptiveMonitoringLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x19\n\x11monitored_segment\x18\x02 \x01(\t\x12\x31\n\x15\x64\x65tected_threat_level\x18\x03 \x01(\x0e\x32\x12.seigr.ThreatLevel\x12\x17\n\x0f\x63heck_timestamp\x18\x04 \x01(\t\x12\x1c\n\x14triggered_escalation\x18\x05 \x01(\x08\x12\x15\n\rescalation_id\x18\x06 \x01(\t\x12\x43\n\x0clog_metadata\x18\x07 \x03(\x0b\x32-.seigr.AdaptiveMonitoringLog.LogMetadataEntry\x12\x1d\n\x15response_action_taken\x18\x08 \x01(\t\x12\x1c\n\x14next_check_scheduled\x18\t \x01(\t\x12\x1a\n\x12\x64\x65tection_accuracy\x18\n \x01(\x02\x12\x1b\n\x13monitoring_operator\x18\x0b \x01(\t\x12Q\n\x13\x61\x64\x61ptive_parameters\x18\x0c \x03(\x0b\x32\x34.seigr.AdaptiveMonitoringLog.AdaptiveParametersEntry\x1a\x32\n\x10LogMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x39\n\x17\x41\x64\x61ptiveParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\x8a\x01\n\x0e\x45scalationType\x12\x1d\n\x19\x45SCALATION_TYPE_UNDEFINED\x10\x00\x12\x16\n\x12THREAT_REPLICATION\x10\x01\x12\x0e\n\nALERT_ONLY\x10\x02\x12\x13\n\x0fSYSTEM_LOCKDOWN\x10\x03\x12\x1c\n\x18\x41\x44\x41PTIVE_RECONFIGURATION\x10\x04\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'monitoring_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _ESCALATION_METADATAENTRY._options = None
  _ESCALATION_METADATAENTRY._serialized_options = b'8\001'
  _ESCALATIONHISTORY_ADDITIONALINFOENTRY._options = None
  _ESCALATIONHISTORY_ADDITIONALINFOENTRY._serialized_options = b'8\001'
  _MONITORINGCONFIG_CONFIGMETADATAENTRY._options = None
  _MONITORINGCONFIG_CONFIGMETADATAENTRY._serialized_options = b'8\001'
  _ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY._options = None
  _ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY._serialized_options = b'8\001'
  _ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY._options = None
  _ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY._serialized_options = b'8\001'
  _ESCALATIONTYPE._serialized_start=1936
  _ESCALATIONTYPE._serialized_end=2074
  _ESCALATION._serialized_start=42
  _ESCALATION._serialized_end=583
  _ESCALATION_METADATAENTRY._serialized_start=536
  _ESCALATION_METADATAENTRY._serialized_end=583
  _ESCALATIONHISTORY._serialized_start=586
  _ESCALATIONHISTORY._serialized_end=827
  _ESCALATIONHISTORY_ADDITIONALINFOENTRY._serialized_start=774
  _ESCALATIONHISTORY_ADDITIONALINFOENTRY._serialized_end=827
  _MONITORINGCONFIG._serialized_start=830
  _MONITORINGCONFIG._serialized_end=1354
  _MONITORINGCONFIG_CONFIGMETADATAENTRY._serialized_start=1301
  _MONITORINGCONFIG_CONFIGMETADATAENTRY._serialized_end=1354
  _ADAPTIVEMONITORINGLOG._serialized_start=1357
  _ADAPTIVEMONITORINGLOG._serialized_end=1933
  _ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY._serialized_start=1824
  _ADAPTIVEMONITORINGLOG_LOGMETADATAENTRY._serialized_end=1874
  _ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY._serialized_start=1876
  _ADAPTIVEMONITORINGLOG_ADAPTIVEPARAMETERSENTRY._serialized_end=1933
# @@protoc_insertion_point(module_scope)
