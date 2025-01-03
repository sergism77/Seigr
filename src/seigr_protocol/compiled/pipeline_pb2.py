# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: pipeline.proto
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
    'pipeline.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0epipeline.proto\x12\x05seigr\"\x93\x07\n\rPipelineStage\x12\x12\n\nstage_name\x18\x01 \x01(\t\x12\x16\n\x0eoperation_type\x18\x02 \x01(\t\x12\x14\n\x0c\x64\x65pendencies\x18\x03 \x03(\t\x12 \n\x18\x63onditional_dependencies\x18\x04 \x03(\t\x12*\n\rtrigger_event\x18\x05 \x01(\x0e\x32\x13.seigr.TriggerEvent\x12\x38\n\nparameters\x18\x06 \x03(\x0b\x32$.seigr.PipelineStage.ParametersEntry\x12\x30\n\x0cstage_status\x18\x07 \x01(\x0e\x32\x1a.seigr.PipelineStageStatus\x12\x17\n\x0f\x61ssigned_hyphen\x18\x08 \x01(\t\x12\x12\n\nstart_time\x18\t \x01(\t\x12\x10\n\x08\x65nd_time\x18\n \x01(\t\x12\x16\n\x0e\x66\x61ilure_reason\x18\x0b \x01(\t\x12\x37\n\x11recovery_strategy\x18\x0c \x01(\x0e\x32\x1c.seigr.ErrorRecoveryStrategy\x12\x16\n\x0eretry_attempts\x18\r \x01(\x05\x12\x45\n\x11\x65xecution_context\x18\x0e \x03(\x0b\x32*.seigr.PipelineStage.ExecutionContextEntry\x12\x1c\n\x14\x63ondition_expression\x18\x0f \x01(\t\x12\x18\n\x10\x64uration_seconds\x18\x10 \x01(\x05\x12\x1a\n\x12memory_usage_bytes\x18\x11 \x01(\x03\x12\x1b\n\x13\x63pu_load_percentage\x18\x12 \x01(\x02\x12\x1d\n\x15\x61\x64\x61ptive_retry_policy\x18\x13 \x01(\t\x12\x15\n\ris_checkpoint\x18\x14 \x01(\x08\x12I\n\x13resource_allocation\x18\x15 \x03(\x0b\x32,.seigr.PipelineStage.ResourceAllocationEntry\x1a\x31\n\x0fParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x37\n\x15\x45xecutionContextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x39\n\x17ResourceAllocationEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb7\x03\n\x08Pipeline\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12$\n\x06stages\x18\x03 \x03(\x0b\x32\x14.seigr.PipelineStage\x12.\n\x0eoverall_status\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12\x12\n\ncreated_by\x18\x05 \x01(\t\x12\x12\n\ncreated_at\x18\x06 \x01(\t\x12\x14\n\x0c\x63ompleted_at\x18\x07 \x01(\t\x12/\n\x08metadata\x18\x08 \x03(\x0b\x32\x1d.seigr.Pipeline.MetadataEntry\x12\x14\n\x0ctotal_stages\x18\t \x01(\x05\x12\x19\n\x11successful_stages\x18\n \x01(\x05\x12\x15\n\rfailed_stages\x18\x0b \x01(\x05\x12\'\n\x1f\x61\x64\x61ptive_error_handling_enabled\x18\x0c \x01(\x08\x12!\n\x19\x63heckpoint_based_rollback\x18\r \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xa6\x03\n\x0ePipelineConfig\x12\x1d\n\x15max_concurrent_stages\x18\x01 \x01(\x05\x12\x1b\n\x13\x64\x65\x66\x61ult_retry_limit\x18\x02 \x01(\x05\x12\x17\n\x0ftimeout_seconds\x18\x03 \x01(\x05\x12\"\n\x1a\x65nable_error_notifications\x18\x04 \x01(\x08\x12\x42\n\x0f\x63onfig_metadata\x18\x05 \x03(\x0b\x32).seigr.PipelineConfig.ConfigMetadataEntry\x12\x1d\n\x15global_error_strategy\x18\x06 \x01(\t\x12\x1c\n\x14\x61uto_resume_on_error\x18\x07 \x01(\x08\x12\x1f\n\x17\x64ynamic_stage_insertion\x18\x08 \x01(\x08\x12 \n\x18max_resource_utilization\x18\t \x01(\x05\x12 \n\x18\x65nable_real_time_scaling\x18\n \x01(\x08\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc5\x01\n\x18PipelineExecutionHistory\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12\x32\n\nexecutions\x18\x02 \x03(\x0b\x32\x1e.seigr.PipelineExecutionRecord\x12\x12\n\ntotal_runs\x18\x03 \x01(\x05\x12\x17\n\x0fsuccessful_runs\x18\x04 \x01(\x05\x12\x13\n\x0b\x66\x61iled_runs\x18\x05 \x01(\x05\x12\x1e\n\x16\x61\x64\x61ptive_retries_count\x18\x06 \x01(\x05\"\xf2\x02\n\x17PipelineExecutionRecord\x12\x14\n\x0c\x65xecution_id\x18\x01 \x01(\t\x12\x12\n\nstarted_at\x18\x02 \x01(\t\x12\x10\n\x08\x65nded_at\x18\x03 \x01(\t\x12&\n\x06result\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12Q\n\x12\x65xecution_metadata\x18\x05 \x03(\x0b\x32\x35.seigr.PipelineExecutionRecord.ExecutionMetadataEntry\x12\x18\n\x10stages_completed\x18\x06 \x01(\x05\x12\x15\n\rstages_failed\x18\x07 \x01(\x05\x12\x17\n\x0f\x66\x61ilure_summary\x18\x08 \x01(\t\x12\x1c\n\x14\x61\x64\x61ptive_adjustments\x18\t \x01(\t\x1a\x38\n\x16\x45xecutionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xeb\x03\n\x12PipelineMonitoring\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12$\n\x06stages\x18\x02 \x03(\x0b\x32\x14.seigr.PipelineStage\x12\x15\n\rcurrent_stage\x18\x03 \x01(\t\x12.\n\x0eoverall_status\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12\x18\n\x10stages_completed\x18\x05 \x01(\x05\x12\x16\n\x0estages_pending\x18\x06 \x01(\x05\x12\x13\n\x0blast_update\x18\x07 \x01(\t\x12N\n\x13monitoring_metadata\x18\x08 \x03(\x0b\x32\x31.seigr.PipelineMonitoring.MonitoringMetadataEntry\x12 \n\x18total_memory_usage_bytes\x18\t \x01(\x03\x12#\n\x1b\x61verage_cpu_load_percentage\x18\n \x01(\x02\x12\x17\n\x0flast_checkpoint\x18\x0b \x01(\t\x12!\n\x19\x65stimated_completion_time\x18\x0c \x01(\t\x1a\x39\n\x17MonitoringMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf4\x04\n\x11PipelineAnalytics\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12 \n\x18\x61verage_duration_seconds\x18\x02 \x01(\x02\x12\x1c\n\x14\x61verage_success_rate\x18\x03 \x01(\x02\x12&\n\x1e\x66requently_failed_stages_count\x18\x04 \x01(\x05\x12N\n\x14stage_failure_counts\x18\x05 \x03(\x0b\x32\x30.seigr.PipelineAnalytics.StageFailureCountsEntry\x12\x18\n\x10last_analyzed_at\x18\x06 \x01(\t\x12(\n average_adaptive_retries_per_run\x18\x07 \x01(\x02\x12G\n\x10\x66\x61ilure_patterns\x18\x08 \x03(\x0b\x32-.seigr.PipelineAnalytics.FailurePatternsEntry\x12T\n\x17recovery_strategy_usage\x18\t \x03(\x0b\x32\x33.seigr.PipelineAnalytics.RecoveryStrategyUsageEntry\x1a\x39\n\x17StageFailureCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x36\n\x14\x46\x61ilurePatternsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a<\n\x1aRecoveryStrategyUsageEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01*\xa3\x01\n\x0fOperationStatus\x12\x1e\n\x1aOPERATION_STATUS_UNDEFINED\x10\x00\x12\x15\n\x11OPERATION_SUCCESS\x10\x01\x12\x15\n\x11OPERATION_FAILURE\x10\x02\x12\x15\n\x11OPERATION_PENDING\x10\x03\x12\x15\n\x11OPERATION_RUNNING\x10\x04\x12\x14\n\x10OPERATION_PAUSED\x10\x05*\x90\x01\n\x0cTriggerEvent\x12\x12\n\x0eON_DATA_CHANGE\x10\x00\x12\r\n\tON_ACCESS\x10\x01\x12\x18\n\x14ON_INTEGRITY_FAILURE\x10\x02\x12\x15\n\x11ON_CUSTOM_TRIGGER\x10\x03\x12\x15\n\x11ON_MANUAL_REQUEST\x10\x04\x12\x15\n\x11ON_EXTERNAL_EVENT\x10\x05*\xac\x02\n\x13PipelineStageStatus\x12#\n\x1fPIPELINE_STAGE_STATUS_UNDEFINED\x10\x00\x12\x1e\n\x1aPIPELINE_STAGE_INITIALIZED\x10\x01\x12\x1a\n\x16PIPELINE_STAGE_RUNNING\x10\x02\x12\x1c\n\x18PIPELINE_STAGE_COMPLETED\x10\x03\x12\x19\n\x15PIPELINE_STAGE_FAILED\x10\x04\x12\x1a\n\x16PIPELINE_STAGE_SKIPPED\x10\x05\x12\x1b\n\x17PIPELINE_STAGE_RETRYING\x10\x06\x12\x1b\n\x17PIPELINE_STAGE_CANCELED\x10\x07\x12%\n!PIPELINE_STAGE_ADAPTIVE_RESOLVING\x10\x08*\xcf\x01\n\x15\x45rrorRecoveryStrategy\x12\x16\n\x12RECOVERY_UNDEFINED\x10\x00\x12\x12\n\x0eRECOVERY_RETRY\x10\x01\x12\x11\n\rRECOVERY_SKIP\x10\x02\x12\x1f\n\x1bRECOVERY_TERMINATE_PIPELINE\x10\x03\x12\x1c\n\x18RECOVERY_ALERT_AND_PAUSE\x10\x04\x12\x1b\n\x17RECOVERY_ADAPTIVE_RETRY\x10\x05\x12\x1b\n\x17RECOVERY_REDIRECT_STAGE\x10\x06\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'pipeline_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_PIPELINESTAGE_PARAMETERSENTRY']._loaded_options = None
  _globals['_PIPELINESTAGE_PARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINESTAGE_EXECUTIONCONTEXTENTRY']._loaded_options = None
  _globals['_PIPELINESTAGE_EXECUTIONCONTEXTENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINESTAGE_RESOURCEALLOCATIONENTRY']._loaded_options = None
  _globals['_PIPELINESTAGE_RESOURCEALLOCATIONENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINE_METADATAENTRY']._loaded_options = None
  _globals['_PIPELINE_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINECONFIG_CONFIGMETADATAENTRY']._loaded_options = None
  _globals['_PIPELINECONFIG_CONFIGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY']._loaded_options = None
  _globals['_PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINEMONITORING_MONITORINGMETADATAENTRY']._loaded_options = None
  _globals['_PIPELINEMONITORING_MONITORINGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY']._loaded_options = None
  _globals['_PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINEANALYTICS_FAILUREPATTERNSENTRY']._loaded_options = None
  _globals['_PIPELINEANALYTICS_FAILUREPATTERNSENTRY']._serialized_options = b'8\001'
  _globals['_PIPELINEANALYTICS_RECOVERYSTRATEGYUSAGEENTRY']._loaded_options = None
  _globals['_PIPELINEANALYTICS_RECOVERYSTRATEGYUSAGEENTRY']._serialized_options = b'8\001'
  _globals['_OPERATIONSTATUS']._serialized_start=3509
  _globals['_OPERATIONSTATUS']._serialized_end=3672
  _globals['_TRIGGEREVENT']._serialized_start=3675
  _globals['_TRIGGEREVENT']._serialized_end=3819
  _globals['_PIPELINESTAGESTATUS']._serialized_start=3822
  _globals['_PIPELINESTAGESTATUS']._serialized_end=4122
  _globals['_ERRORRECOVERYSTRATEGY']._serialized_start=4125
  _globals['_ERRORRECOVERYSTRATEGY']._serialized_end=4332
  _globals['_PIPELINESTAGE']._serialized_start=26
  _globals['_PIPELINESTAGE']._serialized_end=941
  _globals['_PIPELINESTAGE_PARAMETERSENTRY']._serialized_start=776
  _globals['_PIPELINESTAGE_PARAMETERSENTRY']._serialized_end=825
  _globals['_PIPELINESTAGE_EXECUTIONCONTEXTENTRY']._serialized_start=827
  _globals['_PIPELINESTAGE_EXECUTIONCONTEXTENTRY']._serialized_end=882
  _globals['_PIPELINESTAGE_RESOURCEALLOCATIONENTRY']._serialized_start=884
  _globals['_PIPELINESTAGE_RESOURCEALLOCATIONENTRY']._serialized_end=941
  _globals['_PIPELINE']._serialized_start=944
  _globals['_PIPELINE']._serialized_end=1383
  _globals['_PIPELINE_METADATAENTRY']._serialized_start=1336
  _globals['_PIPELINE_METADATAENTRY']._serialized_end=1383
  _globals['_PIPELINECONFIG']._serialized_start=1386
  _globals['_PIPELINECONFIG']._serialized_end=1808
  _globals['_PIPELINECONFIG_CONFIGMETADATAENTRY']._serialized_start=1755
  _globals['_PIPELINECONFIG_CONFIGMETADATAENTRY']._serialized_end=1808
  _globals['_PIPELINEEXECUTIONHISTORY']._serialized_start=1811
  _globals['_PIPELINEEXECUTIONHISTORY']._serialized_end=2008
  _globals['_PIPELINEEXECUTIONRECORD']._serialized_start=2011
  _globals['_PIPELINEEXECUTIONRECORD']._serialized_end=2381
  _globals['_PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY']._serialized_start=2325
  _globals['_PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY']._serialized_end=2381
  _globals['_PIPELINEMONITORING']._serialized_start=2384
  _globals['_PIPELINEMONITORING']._serialized_end=2875
  _globals['_PIPELINEMONITORING_MONITORINGMETADATAENTRY']._serialized_start=2818
  _globals['_PIPELINEMONITORING_MONITORINGMETADATAENTRY']._serialized_end=2875
  _globals['_PIPELINEANALYTICS']._serialized_start=2878
  _globals['_PIPELINEANALYTICS']._serialized_end=3506
  _globals['_PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY']._serialized_start=3331
  _globals['_PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY']._serialized_end=3388
  _globals['_PIPELINEANALYTICS_FAILUREPATTERNSENTRY']._serialized_start=3390
  _globals['_PIPELINEANALYTICS_FAILUREPATTERNSENTRY']._serialized_end=3444
  _globals['_PIPELINEANALYTICS_RECOVERYSTRATEGYUSAGEENTRY']._serialized_start=3446
  _globals['_PIPELINEANALYTICS_RECOVERYSTRATEGYUSAGEENTRY']._serialized_end=3506
# @@protoc_insertion_point(module_scope)
