# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: error_handling.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x14\x65rror_handling.proto\x12\x05seigr"\xd5\x03\n\rErrorLogEntry\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12&\n\x08severity\x18\x02 \x01(\x0e\x32\x14.seigr.ErrorSeverity\x12\x11\n\tcomponent\x18\x03 \x01(\t\x12\x0f\n\x07message\x18\x04 \x01(\t\x12\x0f\n\x07\x64\x65tails\x18\x05 \x01(\t\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12\x10\n\x08resolved\x18\x07 \x01(\x08\x12\x1c\n\x14resolution_timestamp\x18\x08 \x01(\t\x12\x32\n\x07\x63ontext\x18\t \x03(\x0b\x32!.seigr.ErrorLogEntry.ContextEntry\x12;\n\x13resolution_strategy\x18\n \x01(\x0e\x32\x1e.seigr.ErrorResolutionStrategy\x12\x16\n\x0e\x64\x65pendency_ids\x18\x0b \x03(\t\x12\x19\n\x11user_impact_level\x18\x0c \x01(\t\x12\x12\n\nerror_code\x18\r \x01(\t\x12\x14\n\x0csource_trace\x18\x0e \x01(\t\x12\x14\n\x0cimpact_scope\x18\x0f \x01(\t\x1a.\n\x0c\x43ontextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xae\x04\n\nErrorStats\x12\x14\n\x0ctotal_errors\x18\x01 \x01(\x05\x12\x19\n\x11unresolved_errors\x18\x02 \x01(\x05\x12>\n\x0fseverity_counts\x18\x03 \x03(\x0b\x32%.seigr.ErrorStats.SeverityCountsEntry\x12\x19\n\x11most_recent_error\x18\x04 \x01(\t\x12K\n\x16\x63omponent_error_counts\x18\x05 \x03(\x0b\x32+.seigr.ErrorStats.ComponentErrorCountsEntry\x12\x42\n\x11resolution_counts\x18\x06 \x03(\x0b\x32\'.seigr.ErrorStats.ResolutionCountsEntry\x12\x13\n\x0b\x65rror_trend\x18\x07 \x01(\t\x12#\n\x1b\x61vg_resolution_time_seconds\x18\x08 \x01(\x01\x12\x1c\n\x14\x64isaster_error_count\x18\t \x01(\x05\x1a\x35\n\x13SeverityCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a;\n\x19\x43omponentErrorCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x37\n\x15ResolutionCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01"\xd8\x02\n\x12\x45rrorTrendAnalysis\x12\x19\n\x11trend_analysis_id\x18\x01 \x01(\t\x12\x11\n\tcomponent\x18\x02 \x01(\t\x12\x1d\n\x15recurring_error_count\x18\x03 \x01(\x05\x12\x19\n\x11trend_description\x18\x04 \x01(\t\x12\x13\n\x0btime_period\x18\x05 \x01(\t\x12N\n\x13\x61\x64\x64itional_metadata\x18\x06 \x03(\x0b\x32\x31.seigr.ErrorTrendAnalysis.AdditionalMetadataEntry\x12\x1a\n\x12recurrence_pattern\x18\x07 \x01(\t\x12\x1e\n\x16\x61uto_adjusted_severity\x18\x08 \x01(\x08\x1a\x39\n\x17\x41\x64\x64itionalMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xe9\x03\n\x0eRecoveryConfig\x12\x11\n\tcomponent\x18\x01 \x01(\t\x12\x33\n\x15max_severity_to_retry\x18\x02 \x01(\x0e\x32\x14.seigr.ErrorSeverity\x12\x1a\n\x12max_retry_attempts\x18\x03 \x01(\x05\x12\x1e\n\x16retry_interval_seconds\x18\x04 \x01(\x05\x12\x19\n\x11notify_on_failure\x18\x05 \x01(\x08\x12\x38\n\x10\x64\x65\x66\x61ult_strategy\x18\x06 \x01(\x0e\x32\x1e.seigr.ErrorResolutionStrategy\x12J\n\x13severity_strategies\x18\x07 \x03(\x0b\x32-.seigr.RecoveryConfig.SeverityStrategiesEntry\x12\x1a\n\x12\x65scalation_contact\x18\x08 \x01(\t\x12\x19\n\x11recovery_playbook\x18\t \x01(\t\x12 \n\x18\x65nable_adaptive_strategy\x18\n \x01(\x08\x1aY\n\x17SeverityStrategiesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12-\n\x05value\x18\x02 \x01(\x0e\x32\x1e.seigr.ErrorResolutionStrategy:\x02\x38\x01"\xe2\x02\n\x11\x45rrorNotification\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12&\n\x08severity\x18\x02 \x01(\x0e\x32\x14.seigr.ErrorSeverity\x12\x1a\n\x12\x61\x66\x66\x65\x63ted_component\x18\x03 \x01(\t\x12\x15\n\ralert_message\x18\x04 \x01(\t\x12\x14\n\x0c\x63ontact_info\x18\x05 \x01(\t\x12\x14\n\x0ctriggered_at\x18\x06 \x01(\t\x12\x43\n\x0e\x61lert_metadata\x18\x07 \x03(\x0b\x32+.seigr.ErrorNotification.AlertMetadataEntry\x12\x1b\n\x13\x65scalation_pathways\x18\x08 \x03(\t\x12\x1c\n\x14recent_error_history\x18\t \x03(\t\x1a\x34\n\x12\x41lertMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xb3\x01\n\rErrorSeverity\x12\x1c\n\x18\x45RROR_SEVERITY_UNDEFINED\x10\x00\x12\x16\n\x12\x45RROR_SEVERITY_LOW\x10\x01\x12\x19\n\x15\x45RROR_SEVERITY_MEDIUM\x10\x02\x12\x17\n\x13\x45RROR_SEVERITY_HIGH\x10\x03\x12\x1b\n\x17\x45RROR_SEVERITY_CRITICAL\x10\x04\x12\x1b\n\x17\x45RROR_SEVERITY_DISASTER\x10\x05*\xd9\x02\n\x17\x45rrorResolutionStrategy\x12\x1c\n\x18\x45RROR_STRATEGY_UNDEFINED\x10\x00\x12\x18\n\x14\x45RROR_STRATEGY_RETRY\x10\x01\x12#\n\x1f\x45RROR_STRATEGY_LOG_AND_CONTINUE\x10\x02\x12\x1c\n\x18\x45RROR_STRATEGY_TERMINATE\x10\x03\x12"\n\x1e\x45RROR_STRATEGY_ALERT_AND_PAUSE\x10\x04\x12%\n!ERROR_STRATEGY_FALLBACK_OPERATION\x10\x05\x12\'\n#ERROR_STRATEGY_ESCALATE_IMMEDIATELY\x10\x06\x12,\n(ERROR_STRATEGY_ROLLING_BACK_DEPENDENCIES\x10\x07\x12!\n\x1d\x45RROR_STRATEGY_ADAPTIVE_RETRY\x10\x08\x62\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "error_handling_pb2", globals())
if _descriptor._USE_C_DESCRIPTORS == False:

    DESCRIPTOR._options = None
    _ERRORLOGENTRY_CONTEXTENTRY._options = None
    _ERRORLOGENTRY_CONTEXTENTRY._serialized_options = b"8\001"
    _ERRORSTATS_SEVERITYCOUNTSENTRY._options = None
    _ERRORSTATS_SEVERITYCOUNTSENTRY._serialized_options = b"8\001"
    _ERRORSTATS_COMPONENTERRORCOUNTSENTRY._options = None
    _ERRORSTATS_COMPONENTERRORCOUNTSENTRY._serialized_options = b"8\001"
    _ERRORSTATS_RESOLUTIONCOUNTSENTRY._options = None
    _ERRORSTATS_RESOLUTIONCOUNTSENTRY._serialized_options = b"8\001"
    _ERRORTRENDANALYSIS_ADDITIONALMETADATAENTRY._options = None
    _ERRORTRENDANALYSIS_ADDITIONALMETADATAENTRY._serialized_options = b"8\001"
    _RECOVERYCONFIG_SEVERITYSTRATEGIESENTRY._options = None
    _RECOVERYCONFIG_SEVERITYSTRATEGIESENTRY._serialized_options = b"8\001"
    _ERRORNOTIFICATION_ALERTMETADATAENTRY._options = None
    _ERRORNOTIFICATION_ALERTMETADATAENTRY._serialized_options = b"8\001"
    _ERRORSEVERITY._serialized_start = 2261
    _ERRORSEVERITY._serialized_end = 2440
    _ERRORRESOLUTIONSTRATEGY._serialized_start = 2443
    _ERRORRESOLUTIONSTRATEGY._serialized_end = 2788
    _ERRORLOGENTRY._serialized_start = 32
    _ERRORLOGENTRY._serialized_end = 501
    _ERRORLOGENTRY_CONTEXTENTRY._serialized_start = 455
    _ERRORLOGENTRY_CONTEXTENTRY._serialized_end = 501
    _ERRORSTATS._serialized_start = 504
    _ERRORSTATS._serialized_end = 1062
    _ERRORSTATS_SEVERITYCOUNTSENTRY._serialized_start = 891
    _ERRORSTATS_SEVERITYCOUNTSENTRY._serialized_end = 944
    _ERRORSTATS_COMPONENTERRORCOUNTSENTRY._serialized_start = 946
    _ERRORSTATS_COMPONENTERRORCOUNTSENTRY._serialized_end = 1005
    _ERRORSTATS_RESOLUTIONCOUNTSENTRY._serialized_start = 1007
    _ERRORSTATS_RESOLUTIONCOUNTSENTRY._serialized_end = 1062
    _ERRORTRENDANALYSIS._serialized_start = 1065
    _ERRORTRENDANALYSIS._serialized_end = 1409
    _ERRORTRENDANALYSIS_ADDITIONALMETADATAENTRY._serialized_start = 1352
    _ERRORTRENDANALYSIS_ADDITIONALMETADATAENTRY._serialized_end = 1409
    _RECOVERYCONFIG._serialized_start = 1412
    _RECOVERYCONFIG._serialized_end = 1901
    _RECOVERYCONFIG_SEVERITYSTRATEGIESENTRY._serialized_start = 1812
    _RECOVERYCONFIG_SEVERITYSTRATEGIESENTRY._serialized_end = 1901
    _ERRORNOTIFICATION._serialized_start = 1904
    _ERRORNOTIFICATION._serialized_end = 2258
    _ERRORNOTIFICATION_ALERTMETADATAENTRY._serialized_start = 2206
    _ERRORNOTIFICATION_ALERTMETADATAENTRY._serialized_end = 2258
# @@protoc_insertion_point(module_scope)
