# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: alerting.proto
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
    'alerting.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0e\x61lerting.proto\x12\x0eseigr.alerting\x1a\x1fgoogle/protobuf/timestamp.proto\"+\n\rAlertMetadata\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t\"\xe4\x01\n\x0c\x41lertContext\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x12\n\nsession_id\x18\x02 \x01(\t\x12\x0f\n\x07user_id\x18\x03 \x01(\t\x12\x10\n\x08trace_id\x18\x04 \x01(\t\x12O\n\x12\x61\x64\x64itional_context\x18\x05 \x03(\x0b\x32\x33.seigr.alerting.AlertContext.AdditionalContextEntry\x1a\x38\n\x16\x41\x64\x64itionalContextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x9b\x02\n\x0f\x41lertResolution\x12\x16\n\x0eresolved_by_id\x18\x01 \x01(\t\x12\x1a\n\x12resolution_details\x18\x02 \x01(\t\x12/\n\x0bresolved_at\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x31\n\x0c\x61\x63tion_taken\x18\x04 \x01(\x0e\x32\x1b.seigr.alerting.AlertAction\x12?\n\x08metadata\x18\x05 \x03(\x0b\x32-.seigr.alerting.AlertResolution.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xba\x02\n\x0f\x41lertEscalation\x12\x15\n\rescalation_id\x18\x01 \x01(\t\x12\x14\n\x0c\x65scalated_by\x18\x02 \x01(\t\x12\x19\n\x11\x65scalation_reason\x18\x03 \x01(\t\x12\x33\n\x0cnew_severity\x18\x04 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12\x38\n\x14\x65scalation_timestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12?\n\x08metadata\x18\x06 \x03(\x0b\x32-.seigr.alerting.AlertEscalation.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"g\n\x14\x41lertEscalationChain\x12\x39\n\x10\x65scalation_steps\x18\x01 \x03(\x0b\x32\x1f.seigr.alerting.AlertEscalation\x12\x14\n\x0c\x66inal_status\x18\x02 \x01(\t\"\xc7\x04\n\x05\x41lert\x12\x10\n\x08\x61lert_id\x18\x01 \x01(\t\x12\'\n\x04type\x18\x02 \x01(\x0e\x32\x19.seigr.alerting.AlertType\x12/\n\x08severity\x18\x03 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12\x0f\n\x07message\x18\x04 \x01(\t\x12-\n\ttimestamp\x18\x05 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x18\n\x10source_component\x18\x06 \x01(\t\x12:\n\x0etrigger_source\x18\x07 \x01(\x0e\x32\".seigr.alerting.AlertTriggerSource\x12-\n\x07\x63ontext\x18\x08 \x01(\x0b\x32\x1c.seigr.alerting.AlertContext\x12\x35\n\x08metadata\x18\t \x03(\x0b\x32#.seigr.alerting.Alert.MetadataEntry\x12\x33\n\nresolution\x18\n \x01(\x0b\x32\x1f.seigr.alerting.AlertResolution\x12>\n\x10\x65scalation_chain\x18\x0b \x01(\x0b\x32$.seigr.alerting.AlertEscalationChain\x12\x30\n\x0blast_action\x18\x0c \x01(\x0e\x32\x1b.seigr.alerting.AlertAction\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xfa\x02\n\tAlertRule\x12\x0f\n\x07rule_id\x18\x01 \x01(\t\x12-\n\nalert_type\x18\x02 \x01(\x0e\x32\x19.seigr.alerting.AlertType\x12\x33\n\x0cmin_severity\x18\x03 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12\x1c\n\x14\x63ondition_expression\x18\x04 \x01(\t\x12\x12\n\nis_enabled\x18\x05 \x01(\x08\x12\x18\n\x10\x61lert_recipients\x18\x06 \x03(\t\x12\x1c\n\x14\x65scalation_policy_id\x18\x07 \x01(\t\x12\x39\n\x08metadata\x18\x08 \x03(\x0b\x32\'.seigr.alerting.AlertRule.MetadataEntry\x12\"\n\x1a\x64ynamic_thresholds_enabled\x18\t \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb5\x05\n\x17\x41lertNotificationConfig\x12\x11\n\tconfig_id\x18\x01 \x01(\t\x12\x1a\n\x12\x64\x65\x66\x61ult_recipients\x18\x02 \x03(\t\x12.\n\x0b\x61lert_types\x18\x03 \x03(\x0e\x32\x19.seigr.alerting.AlertType\x12@\n\x19min_notification_severity\x18\x04 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12#\n\x1b\x65mail_notifications_enabled\x18\x05 \x01(\x08\x12!\n\x19sms_notifications_enabled\x18\x06 \x01(\x08\x12\"\n\x1apush_notifications_enabled\x18\x07 \x01(\x08\x12=\n\x19\x64o_not_disturb_start_time\x18\x08 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12;\n\x17\x64o_not_disturb_end_time\x18\t \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\\\n\x13\x63hannel_preferences\x18\n \x03(\x0b\x32?.seigr.alerting.AlertNotificationConfig.ChannelPreferencesEntry\x12G\n\x08metadata\x18\x0b \x03(\x0b\x32\x35.seigr.alerting.AlertNotificationConfig.MetadataEntry\x1a\x39\n\x17\x43hannelPreferencesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf0\x02\n\x08\x41lertLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x10\n\x08\x61lert_id\x18\x02 \x01(\t\x12/\n\x08severity\x18\x03 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12\x31\n\rlog_timestamp\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x14\n\x0c\x61lert_status\x18\x05 \x01(\t\x12\x33\n\nresolution\x18\x06 \x01(\x0b\x32\x1f.seigr.alerting.AlertResolution\x12\x38\n\x08metadata\x18\x07 \x03(\x0b\x32&.seigr.alerting.AlertLog.MetadataEntry\x12\x13\n\x0b\x65vent_trace\x18\x08 \x03(\t\x12\x13\n\x0bstatus_code\x18\t \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x87\x03\n\x0c\x41lertRequest\x12\x32\n\x0frequested_types\x18\x01 \x03(\x0e\x32\x19.seigr.alerting.AlertType\x12\x33\n\x0cmin_severity\x18\x02 \x01(\x0e\x32\x1d.seigr.alerting.AlertSeverity\x12\x35\n\x11start_time_filter\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x33\n\x0f\x65nd_time_filter\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x19\n\x11source_components\x18\x05 \x03(\t\x12:\n\x07\x66ilters\x18\x06 \x03(\x0b\x32).seigr.alerting.AlertRequest.FiltersEntry\x12\x1b\n\x13include_escalations\x18\x07 \x01(\x08\x1a.\n\x0c\x46iltersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xfc\x01\n\rAlertResponse\x12/\n\rmatching_logs\x18\x01 \x03(\x0b\x32\x18.seigr.alerting.AlertLog\x12\x12\n\nrequest_id\x18\x02 \x01(\t\x12\x36\n\x12response_timestamp\x18\x03 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12=\n\x08metadata\x18\x04 \x03(\x0b\x32+.seigr.alerting.AlertResponse.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xf5\x01\n\tAlertType\x12\x18\n\x14\x41LERT_TYPE_UNDEFINED\x10\x00\x12\x17\n\x13\x41LERT_TYPE_SECURITY\x10\x01\x12\x15\n\x11\x41LERT_TYPE_SYSTEM\x10\x02\x12\x1d\n\x19\x41LERT_TYPE_DATA_INTEGRITY\x10\x03\x12\x16\n\x12\x41LERT_TYPE_NETWORK\x10\x04\x12\x1a\n\x16\x41LERT_TYPE_REPLICATION\x10\x05\x12\x1d\n\x19\x41LERT_TYPE_RESOURCE_USAGE\x10\x06\x12\x15\n\x11\x41LERT_TYPE_CUSTOM\x10\x07\x12\x15\n\x11\x41LERT_TYPE_NOESIS\x10\x08*\xb3\x01\n\rAlertSeverity\x12\x1c\n\x18\x41LERT_SEVERITY_UNDEFINED\x10\x00\x12\x17\n\x13\x41LERT_SEVERITY_INFO\x10\x01\x12\x1a\n\x16\x41LERT_SEVERITY_WARNING\x10\x02\x12\x1b\n\x17\x41LERT_SEVERITY_CRITICAL\x10\x03\x12\x18\n\x14\x41LERT_SEVERITY_FATAL\x10\x04\x12\x18\n\x14\x41LERT_SEVERITY_ERROR\x10\x05*\x9a\x01\n\x12\x41lertTriggerSource\x12\x1b\n\x17\x41LERT_TRIGGER_UNDEFINED\x10\x00\x12\x1b\n\x17\x41LERT_TRIGGER_AUTOMATED\x10\x01\x12\x18\n\x14\x41LERT_TRIGGER_MANUAL\x10\x02\x12\x1a\n\x16\x41LERT_TRIGGER_EXTERNAL\x10\x03\x12\x14\n\x10\x41LERT_TRIGGER_AI\x10\x04*\xc3\x01\n\x0b\x41lertAction\x12\x1a\n\x16\x41LERT_ACTION_UNDEFINED\x10\x00\x12\x1f\n\x1b\x41LERT_ACTION_AUTO_RECOVERED\x10\x01\x12$\n ALERT_ACTION_MANUAL_INTERVENTION\x10\x02\x12\x1a\n\x16\x41LERT_ACTION_ESCALATED\x10\x03\x12\x18\n\x14\x41LERT_ACTION_IGNORED\x10\x04\x12\x1b\n\x17\x41LERT_ACTION_SUPPRESSED\x10\x05\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'alerting_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_ALERTCONTEXT_ADDITIONALCONTEXTENTRY']._loaded_options = None
  _globals['_ALERTCONTEXT_ADDITIONALCONTEXTENTRY']._serialized_options = b'8\001'
  _globals['_ALERTRESOLUTION_METADATAENTRY']._loaded_options = None
  _globals['_ALERTRESOLUTION_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTESCALATION_METADATAENTRY']._loaded_options = None
  _globals['_ALERTESCALATION_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERT_METADATAENTRY']._loaded_options = None
  _globals['_ALERT_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTRULE_METADATAENTRY']._loaded_options = None
  _globals['_ALERTRULE_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTNOTIFICATIONCONFIG_CHANNELPREFERENCESENTRY']._loaded_options = None
  _globals['_ALERTNOTIFICATIONCONFIG_CHANNELPREFERENCESENTRY']._serialized_options = b'8\001'
  _globals['_ALERTNOTIFICATIONCONFIG_METADATAENTRY']._loaded_options = None
  _globals['_ALERTNOTIFICATIONCONFIG_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTLOG_METADATAENTRY']._loaded_options = None
  _globals['_ALERTLOG_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTREQUEST_FILTERSENTRY']._loaded_options = None
  _globals['_ALERTREQUEST_FILTERSENTRY']._serialized_options = b'8\001'
  _globals['_ALERTRESPONSE_METADATAENTRY']._loaded_options = None
  _globals['_ALERTRESPONSE_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALERTTYPE']._serialized_start=3735
  _globals['_ALERTTYPE']._serialized_end=3980
  _globals['_ALERTSEVERITY']._serialized_start=3983
  _globals['_ALERTSEVERITY']._serialized_end=4162
  _globals['_ALERTTRIGGERSOURCE']._serialized_start=4165
  _globals['_ALERTTRIGGERSOURCE']._serialized_end=4319
  _globals['_ALERTACTION']._serialized_start=4322
  _globals['_ALERTACTION']._serialized_end=4517
  _globals['_ALERTMETADATA']._serialized_start=67
  _globals['_ALERTMETADATA']._serialized_end=110
  _globals['_ALERTCONTEXT']._serialized_start=113
  _globals['_ALERTCONTEXT']._serialized_end=341
  _globals['_ALERTCONTEXT_ADDITIONALCONTEXTENTRY']._serialized_start=285
  _globals['_ALERTCONTEXT_ADDITIONALCONTEXTENTRY']._serialized_end=341
  _globals['_ALERTRESOLUTION']._serialized_start=344
  _globals['_ALERTRESOLUTION']._serialized_end=627
  _globals['_ALERTRESOLUTION_METADATAENTRY']._serialized_start=580
  _globals['_ALERTRESOLUTION_METADATAENTRY']._serialized_end=627
  _globals['_ALERTESCALATION']._serialized_start=630
  _globals['_ALERTESCALATION']._serialized_end=944
  _globals['_ALERTESCALATION_METADATAENTRY']._serialized_start=580
  _globals['_ALERTESCALATION_METADATAENTRY']._serialized_end=627
  _globals['_ALERTESCALATIONCHAIN']._serialized_start=946
  _globals['_ALERTESCALATIONCHAIN']._serialized_end=1049
  _globals['_ALERT']._serialized_start=1052
  _globals['_ALERT']._serialized_end=1635
  _globals['_ALERT_METADATAENTRY']._serialized_start=580
  _globals['_ALERT_METADATAENTRY']._serialized_end=627
  _globals['_ALERTRULE']._serialized_start=1638
  _globals['_ALERTRULE']._serialized_end=2016
  _globals['_ALERTRULE_METADATAENTRY']._serialized_start=580
  _globals['_ALERTRULE_METADATAENTRY']._serialized_end=627
  _globals['_ALERTNOTIFICATIONCONFIG']._serialized_start=2019
  _globals['_ALERTNOTIFICATIONCONFIG']._serialized_end=2712
  _globals['_ALERTNOTIFICATIONCONFIG_CHANNELPREFERENCESENTRY']._serialized_start=2606
  _globals['_ALERTNOTIFICATIONCONFIG_CHANNELPREFERENCESENTRY']._serialized_end=2663
  _globals['_ALERTNOTIFICATIONCONFIG_METADATAENTRY']._serialized_start=580
  _globals['_ALERTNOTIFICATIONCONFIG_METADATAENTRY']._serialized_end=627
  _globals['_ALERTLOG']._serialized_start=2715
  _globals['_ALERTLOG']._serialized_end=3083
  _globals['_ALERTLOG_METADATAENTRY']._serialized_start=580
  _globals['_ALERTLOG_METADATAENTRY']._serialized_end=627
  _globals['_ALERTREQUEST']._serialized_start=3086
  _globals['_ALERTREQUEST']._serialized_end=3477
  _globals['_ALERTREQUEST_FILTERSENTRY']._serialized_start=3431
  _globals['_ALERTREQUEST_FILTERSENTRY']._serialized_end=3477
  _globals['_ALERTRESPONSE']._serialized_start=3480
  _globals['_ALERTRESPONSE']._serialized_end=3732
  _globals['_ALERTRESPONSE_METADATAENTRY']._serialized_start=580
  _globals['_ALERTRESPONSE_METADATAENTRY']._serialized_end=627
# @@protoc_insertion_point(module_scope)
