# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: script.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "script.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import error_handling_pb2 as error__handling__pb2
import pipeline_pb2 as pipeline__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0cscript.proto\x12\x0cseigr.script\x1a\x14\x65rror_handling.proto\x1a\x0epipeline.proto"\x95\x06\n\x06Script\x12\x11\n\tscript_id\x18\x01 \x01(\t\x12\x10\n\x08language\x18\x02 \x01(\t\x12\x0c\n\x04\x63ode\x18\x03 \x01(\x0c\x12:\n\x0b\x65nvironment\x18\x04 \x03(\x0b\x32%.seigr.script.Script.EnvironmentEntry\x12\x14\n\x0cis_sandboxed\x18\x05 \x01(\x08\x12\x0f\n\x07version\x18\x06 \x01(\t\x12\x11\n\tcode_hash\x18\x07 \x01(\x0c\x12\x16\n\x0emax_runtime_ms\x18\x08 \x01(\x05\x12\x15\n\rmax_memory_mb\x18\t \x01(\x05\x12\x1d\n\x15max_cpu_usage_percent\x18\n \x01(\x05\x12\x19\n\x11max_disk_usage_mb\x18\x0b \x01(\x05\x12\x1e\n\x16\x61llow_external_network\x18\x0c \x01(\x08\x12\x34\n\x0f\x61llowed_actions\x18\r \x03(\x0e\x32\x1b.seigr.script.AllowedAction\x12\x14\n\x0c\x64\x65pendencies\x18\x0e \x03(\t\x12\x45\n\x0e\x65rror_handling\x18\x0f \x01(\x0e\x32-.seigr.error_handling.ErrorResolutionStrategy\x12)\n\tlog_level\x18\x10 \x01(\x0e\x32\x16.seigr.script.LogLevel\x12\x34\n\x08metadata\x18\x11 \x03(\x0b\x32".seigr.script.Script.MetadataEntry\x12\x16\n\x0e\x65nable_tracing\x18\x12 \x01(\x08\x12\x18\n\x10\x65nable_profiling\x18\x13 \x01(\x08\x12\x1b\n\x13requires_user_input\x18\x14 \x01(\x08\x12\x10\n\x08\x65\x63o_mode\x18\x15 \x01(\x08\x12\x1f\n\x17\x65nable_detailed_metrics\x18\x16 \x01(\x08\x1a\x32\n\x10\x45nvironmentEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x80\x03\n\x16ScriptExecutionRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x11\n\tscript_id\x18\x02 \x01(\t\x12S\n\x10input_parameters\x18\x03 \x03(\x0b\x32\x39.seigr.script.ScriptExecutionRequest.InputParametersEntry\x12\x14\n\x0cinitiated_by\x18\x04 \x01(\t\x12\x14\n\x0crequested_at\x18\x05 \x01(\t\x12\x17\n\x0f\x61sync_execution\x18\x06 \x01(\x08\x12\x18\n\x10timeout_limit_ms\x18\x07 \x01(\x05\x12\x16\n\x0epriority_level\x18\x08 \x01(\t\x12\x18\n\x10\x65\x63o_mode_enabled\x18\t \x01(\x08\x12!\n\x19\x65nable_execution_snapshot\x18\n \x01(\x08\x1a\x36\n\x14InputParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xa9\x03\n\x15ScriptExecutionResult\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12\x11\n\tscript_id\x18\x02 \x01(\t\x12\x0f\n\x07success\x18\x03 \x01(\x08\x12\x13\n\x0bresult_data\x18\x04 \x01(\t\x12\x15\n\rerror_message\x18\x05 \x01(\t\x12\x14\n\x0c\x63ompleted_at\x18\x06 \x01(\t\x12V\n\x12\x65xecution_metadata\x18\x07 \x03(\x0b\x32:.seigr.script.ScriptExecutionResult.ExecutionMetadataEntry\x12\x10\n\x08warnings\x18\x08 \x03(\t\x12\x1d\n\x15\x65xecution_duration_ms\x18\t \x01(\x02\x12\x19\n\x11memory_used_bytes\x18\n \x01(\x03\x12\x18\n\x10\x64isk_usage_bytes\x18\x0b \x01(\x03\x12\x1e\n\x16\x65nergy_consumption_kwh\x18\x0c \x01(\x02\x1a\x38\n\x16\x45xecutionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x9e\x03\n\x11\x44\x65pendencyManager\x12\x1a\n\x12local_dependencies\x18\x01 \x03(\t\x12\x1b\n\x13remote_dependencies\x18\x02 \x03(\t\x12T\n\x13\x64\x65pendency_metadata\x18\x03 \x03(\x0b\x32\x37.seigr.script.DependencyManager.DependencyMetadataEntry\x12\x1b\n\x13\x64\x65pendency_checksum\x18\x04 \x01(\t\x12\x1e\n\x16\x61uto_resolve_conflicts\x18\x05 \x01(\x08\x12\x1a\n\x12\x63\x61\x63he_dependencies\x18\x06 \x01(\x08\x12\x1e\n\x16\x64\x65pendency_source_type\x18\x07 \x01(\t\x12\x1e\n\x16max_dependency_size_mb\x18\x08 \x01(\x05\x12&\n\x1e\x64\x65pendency_resolution_strategy\x18\t \x01(\t\x1a\x39\n\x17\x44\x65pendencyMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xda\x03\n\x10ScriptMonitoring\x12\x11\n\tscript_id\x18\x01 \x01(\t\x12\x14\n\x0c\x65xecution_id\x18\x02 \x01(\t\x12\x11\n\tcpu_usage\x18\x03 \x01(\x02\x12\x14\n\x0cmemory_usage\x18\x04 \x01(\x02\x12\x12\n\ndisk_usage\x18\x05 \x01(\x02\x12\x17\n\x0flast_checked_at\x18\x06 \x01(\t\x12\x16\n\x0estatus_message\x18\x07 \x01(\t\x12S\n\x13monitoring_metadata\x18\x08 \x03(\x0b\x32\x36.seigr.script.ScriptMonitoring.MonitoringMetadataEntry\x12\x14\n\x0c\x63urrent_step\x18\t \x01(\x05\x12\x1b\n\x13progress_percentage\x18\n \x01(\t\x12!\n\x19\x66lagged_for_manual_review\x18\x0b \x01(\x08\x12"\n\x1a\x65stimated_energy_usage_kwh\x18\x0c \x01(\x02\x12%\n\x1dis_sandbox_violation_detected\x18\r \x01(\x08\x1a\x39\n\x17MonitoringMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xd7\x04\n\x0cScriptConfig\x12\x1d\n\x15global_max_runtime_ms\x18\x01 \x01(\x05\x12\x1e\n\x16global_memory_limit_mb\x18\x02 \x01(\x05\x12\x1a\n\x12\x65nforce_sandboxing\x18\x03 \x01(\x08\x12I\n\x10\x65nvironment_vars\x18\x04 \x03(\x0b\x32/.seigr.script.ScriptConfig.EnvironmentVarsEntry\x12;\n\x16global_allowed_actions\x18\x05 \x03(\x0e\x32\x1b.seigr.script.AllowedAction\x12\x1a\n\x12\x66\x61llback_script_id\x18\x06 \x01(\t\x12\x1d\n\x15\x65nable_execution_logs\x18\x07 \x01(\x08\x12X\n\x18\x65rror_handling_overrides\x18\x08 \x03(\x0b\x32\x36.seigr.script.ScriptConfig.ErrorHandlingOverridesEntry\x12\x1e\n\x16max_retries_on_failure\x18\t \x01(\x05\x12\x18\n\x10\x65\x63o_mode_default\x18\n \x01(\x08\x12\x1e\n\x16\x65nable_global_snapshot\x18\x0b \x01(\x08\x1a\x36\n\x14\x45nvironmentVarsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a=\n\x1b\x45rrorHandlingOverridesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc5\x02\n\x16ScriptExecutionHistory\x12\x11\n\tscript_id\x18\x01 \x01(\t\x12\x37\n\nexecutions\x18\x02 \x03(\x0b\x32#.seigr.script.ScriptExecutionRecord\x12\x18\n\x10total_executions\x18\x03 \x01(\x05\x12\x1d\n\x15successful_executions\x18\x04 \x01(\x05\x12\x19\n\x11\x66\x61iled_executions\x18\x05 \x01(\x05\x12S\n\x10history_metadata\x18\x06 \x03(\x0b\x32\x39.seigr.script.ScriptExecutionHistory.HistoryMetadataEntry\x1a\x36\n\x14HistoryMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x81\x03\n\x15ScriptExecutionRecord\x12\x14\n\x0c\x65xecution_id\x18\x01 \x01(\t\x12\x13\n\x0b\x65xecuted_at\x18\x02 \x01(\t\x12\x13\n\x0b\x66inished_at\x18\x03 \x01(\t\x12\x36\n\rresult_status\x18\x04 \x01(\x0e\x32\x1f.seigr.pipeline.OperationStatus\x12T\n\x11\x65xecution_details\x18\x05 \x03(\x0b\x32\x39.seigr.script.ScriptExecutionRecord.ExecutionDetailsEntry\x12\x19\n\x11\x65xecution_summary\x18\x06 \x01(\t\x12\x0e\n\x06\x61lerts\x18\x07 \x03(\t\x12\x1a\n\x12\x65\x63o_execution_flag\x18\x08 \x01(\x08\x12\x1a\n\x12snapshot_reference\x18\t \x01(\t\x1a\x37\n\x15\x45xecutionDetailsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xc1\x01\n\rAllowedAction\x12\x1b\n\x17SCRIPT_ACTION_UNDEFINED\x10\x00\x12\x08\n\x04READ\x10\x01\x12\t\n\x05WRITE\x10\x02\x12\x0b\n\x07\x45XECUTE\x10\x03\x12\n\n\x06\x44\x45LETE\x10\x04\x12\x12\n\x0eNETWORK_ACCESS\x10\x05\x12\x0f\n\x0bSYSTEM_CALL\x10\x06\x12\x0b\n\x07LOGGING\x10\x07\x12 \n\x1c\x41\x44\x41PTIVE_RESOURCE_MANAGEMENT\x10\x08\x12\x11\n\rFILE_TRANSFER\x10\t*\x90\x01\n\x08LogLevel\x12\x17\n\x13LOG_LEVEL_UNDEFINED\x10\x00\x12\x13\n\x0fLOG_LEVEL_DEBUG\x10\x01\x12\x12\n\x0eLOG_LEVEL_INFO\x10\x02\x12\x15\n\x11LOG_LEVEL_WARNING\x10\x03\x12\x13\n\x0fLOG_LEVEL_ERROR\x10\x04\x12\x16\n\x12LOG_LEVEL_CRITICAL\x10\x05\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "script_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_SCRIPT_ENVIRONMENTENTRY"]._loaded_options = None
    _globals["_SCRIPT_ENVIRONMENTENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPT_METADATAENTRY"]._loaded_options = None
    _globals["_SCRIPT_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTEXECUTIONREQUEST_INPUTPARAMETERSENTRY"]._loaded_options = None
    _globals["_SCRIPTEXECUTIONREQUEST_INPUTPARAMETERSENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTEXECUTIONRESULT_EXECUTIONMETADATAENTRY"]._loaded_options = None
    _globals["_SCRIPTEXECUTIONRESULT_EXECUTIONMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_DEPENDENCYMANAGER_DEPENDENCYMETADATAENTRY"]._loaded_options = None
    _globals["_DEPENDENCYMANAGER_DEPENDENCYMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTMONITORING_MONITORINGMETADATAENTRY"]._loaded_options = None
    _globals["_SCRIPTMONITORING_MONITORINGMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTCONFIG_ENVIRONMENTVARSENTRY"]._loaded_options = None
    _globals["_SCRIPTCONFIG_ENVIRONMENTVARSENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTCONFIG_ERRORHANDLINGOVERRIDESENTRY"]._loaded_options = None
    _globals["_SCRIPTCONFIG_ERRORHANDLINGOVERRIDESENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTEXECUTIONHISTORY_HISTORYMETADATAENTRY"]._loaded_options = None
    _globals["_SCRIPTEXECUTIONHISTORY_HISTORYMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_SCRIPTEXECUTIONRECORD_EXECUTIONDETAILSENTRY"]._loaded_options = None
    _globals["_SCRIPTEXECUTIONRECORD_EXECUTIONDETAILSENTRY"]._serialized_options = b"8\001"
    _globals["_ALLOWEDACTION"]._serialized_start = 3888
    _globals["_ALLOWEDACTION"]._serialized_end = 4081
    _globals["_LOGLEVEL"]._serialized_start = 4084
    _globals["_LOGLEVEL"]._serialized_end = 4228
    _globals["_SCRIPT"]._serialized_start = 69
    _globals["_SCRIPT"]._serialized_end = 858
    _globals["_SCRIPT_ENVIRONMENTENTRY"]._serialized_start = 759
    _globals["_SCRIPT_ENVIRONMENTENTRY"]._serialized_end = 809
    _globals["_SCRIPT_METADATAENTRY"]._serialized_start = 811
    _globals["_SCRIPT_METADATAENTRY"]._serialized_end = 858
    _globals["_SCRIPTEXECUTIONREQUEST"]._serialized_start = 861
    _globals["_SCRIPTEXECUTIONREQUEST"]._serialized_end = 1245
    _globals["_SCRIPTEXECUTIONREQUEST_INPUTPARAMETERSENTRY"]._serialized_start = 1191
    _globals["_SCRIPTEXECUTIONREQUEST_INPUTPARAMETERSENTRY"]._serialized_end = 1245
    _globals["_SCRIPTEXECUTIONRESULT"]._serialized_start = 1248
    _globals["_SCRIPTEXECUTIONRESULT"]._serialized_end = 1673
    _globals["_SCRIPTEXECUTIONRESULT_EXECUTIONMETADATAENTRY"]._serialized_start = 1617
    _globals["_SCRIPTEXECUTIONRESULT_EXECUTIONMETADATAENTRY"]._serialized_end = 1673
    _globals["_DEPENDENCYMANAGER"]._serialized_start = 1676
    _globals["_DEPENDENCYMANAGER"]._serialized_end = 2090
    _globals["_DEPENDENCYMANAGER_DEPENDENCYMETADATAENTRY"]._serialized_start = 2033
    _globals["_DEPENDENCYMANAGER_DEPENDENCYMETADATAENTRY"]._serialized_end = 2090
    _globals["_SCRIPTMONITORING"]._serialized_start = 2093
    _globals["_SCRIPTMONITORING"]._serialized_end = 2567
    _globals["_SCRIPTMONITORING_MONITORINGMETADATAENTRY"]._serialized_start = 2510
    _globals["_SCRIPTMONITORING_MONITORINGMETADATAENTRY"]._serialized_end = 2567
    _globals["_SCRIPTCONFIG"]._serialized_start = 2570
    _globals["_SCRIPTCONFIG"]._serialized_end = 3169
    _globals["_SCRIPTCONFIG_ENVIRONMENTVARSENTRY"]._serialized_start = 3052
    _globals["_SCRIPTCONFIG_ENVIRONMENTVARSENTRY"]._serialized_end = 3106
    _globals["_SCRIPTCONFIG_ERRORHANDLINGOVERRIDESENTRY"]._serialized_start = 3108
    _globals["_SCRIPTCONFIG_ERRORHANDLINGOVERRIDESENTRY"]._serialized_end = 3169
    _globals["_SCRIPTEXECUTIONHISTORY"]._serialized_start = 3172
    _globals["_SCRIPTEXECUTIONHISTORY"]._serialized_end = 3497
    _globals["_SCRIPTEXECUTIONHISTORY_HISTORYMETADATAENTRY"]._serialized_start = 3443
    _globals["_SCRIPTEXECUTIONHISTORY_HISTORYMETADATAENTRY"]._serialized_end = 3497
    _globals["_SCRIPTEXECUTIONRECORD"]._serialized_start = 3500
    _globals["_SCRIPTEXECUTIONRECORD"]._serialized_end = 3885
    _globals["_SCRIPTEXECUTIONRECORD_EXECUTIONDETAILSENTRY"]._serialized_start = 3830
    _globals["_SCRIPTEXECUTIONRECORD_EXECUTIONDETAILSENTRY"]._serialized_end = 3885
# @@protoc_insertion_point(module_scope)
