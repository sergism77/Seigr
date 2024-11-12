# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pipeline.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0epipeline.proto\x12\x05seigr\"\xf6\x05\n\rPipelineStage\x12\x12\n\nstage_name\x18\x01 \x01(\t\x12\x16\n\x0eoperation_type\x18\x02 \x01(\t\x12\x14\n\x0c\x64\x65pendencies\x18\x03 \x03(\t\x12 \n\x18\x63onditional_dependencies\x18\x04 \x03(\t\x12*\n\rtrigger_event\x18\x05 \x01(\x0e\x32\x13.seigr.TriggerEvent\x12\x38\n\nparameters\x18\x06 \x03(\x0b\x32$.seigr.PipelineStage.ParametersEntry\x12\x30\n\x0cstage_status\x18\x07 \x01(\x0e\x32\x1a.seigr.PipelineStageStatus\x12\x17\n\x0f\x61ssigned_hyphen\x18\x08 \x01(\t\x12\x12\n\nstart_time\x18\t \x01(\t\x12\x10\n\x08\x65nd_time\x18\n \x01(\t\x12\x16\n\x0e\x66\x61ilure_reason\x18\x0b \x01(\t\x12\x37\n\x11recovery_strategy\x18\x0c \x01(\x0e\x32\x1c.seigr.ErrorRecoveryStrategy\x12\x16\n\x0eretry_attempts\x18\r \x01(\x05\x12\x45\n\x11\x65xecution_context\x18\x0e \x03(\x0b\x32*.seigr.PipelineStage.ExecutionContextEntry\x12\x1c\n\x14\x63ondition_expression\x18\x0f \x01(\t\x12\x18\n\x10\x64uration_seconds\x18\x10 \x01(\x05\x12\x1a\n\x12memory_usage_bytes\x18\x11 \x01(\x03\x12\x1b\n\x13\x63pu_load_percentage\x18\x12 \x01(\x02\x12\x1d\n\x15\x61\x64\x61ptive_retry_policy\x18\x13 \x01(\t\x1a\x31\n\x0fParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x37\n\x15\x45xecutionContextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xeb\x02\n\x08Pipeline\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12$\n\x06stages\x18\x03 \x03(\x0b\x32\x14.seigr.PipelineStage\x12.\n\x0eoverall_status\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12\x12\n\ncreated_by\x18\x05 \x01(\t\x12\x12\n\ncreated_at\x18\x06 \x01(\t\x12\x14\n\x0c\x63ompleted_at\x18\x07 \x01(\t\x12/\n\x08metadata\x18\x08 \x03(\x0b\x32\x1d.seigr.Pipeline.MetadataEntry\x12\x14\n\x0ctotal_stages\x18\t \x01(\x05\x12\x19\n\x11successful_stages\x18\n \x01(\x05\x12\x15\n\rfailed_stages\x18\x0b \x01(\x05\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe2\x02\n\x0ePipelineConfig\x12\x1d\n\x15max_concurrent_stages\x18\x01 \x01(\x05\x12\x1b\n\x13\x64\x65\x66\x61ult_retry_limit\x18\x02 \x01(\x05\x12\x17\n\x0ftimeout_seconds\x18\x03 \x01(\x05\x12\"\n\x1a\x65nable_error_notifications\x18\x04 \x01(\x08\x12\x42\n\x0f\x63onfig_metadata\x18\x05 \x03(\x0b\x32).seigr.PipelineConfig.ConfigMetadataEntry\x12\x1d\n\x15global_error_strategy\x18\x06 \x01(\t\x12\x1c\n\x14\x61uto_resume_on_error\x18\x07 \x01(\x08\x12\x1f\n\x17\x64ynamic_stage_insertion\x18\x08 \x01(\x08\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xa5\x01\n\x18PipelineExecutionHistory\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12\x32\n\nexecutions\x18\x02 \x03(\x0b\x32\x1e.seigr.PipelineExecutionRecord\x12\x12\n\ntotal_runs\x18\x03 \x01(\x05\x12\x17\n\x0fsuccessful_runs\x18\x04 \x01(\x05\x12\x13\n\x0b\x66\x61iled_runs\x18\x05 \x01(\x05\"\xd4\x02\n\x17PipelineExecutionRecord\x12\x14\n\x0c\x65xecution_id\x18\x01 \x01(\t\x12\x12\n\nstarted_at\x18\x02 \x01(\t\x12\x10\n\x08\x65nded_at\x18\x03 \x01(\t\x12&\n\x06result\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12Q\n\x12\x65xecution_metadata\x18\x05 \x03(\x0b\x32\x35.seigr.PipelineExecutionRecord.ExecutionMetadataEntry\x12\x18\n\x10stages_completed\x18\x06 \x01(\x05\x12\x15\n\rstages_failed\x18\x07 \x01(\x05\x12\x17\n\x0f\x66\x61ilure_summary\x18\x08 \x01(\t\x1a\x38\n\x16\x45xecutionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xaf\x03\n\x12PipelineMonitoring\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12$\n\x06stages\x18\x02 \x03(\x0b\x32\x14.seigr.PipelineStage\x12\x15\n\rcurrent_stage\x18\x03 \x01(\t\x12.\n\x0eoverall_status\x18\x04 \x01(\x0e\x32\x16.seigr.OperationStatus\x12\x18\n\x10stages_completed\x18\x05 \x01(\x05\x12\x16\n\x0estages_pending\x18\x06 \x01(\x05\x12\x13\n\x0blast_update\x18\x07 \x01(\t\x12N\n\x13monitoring_metadata\x18\x08 \x03(\x0b\x32\x31.seigr.PipelineMonitoring.MonitoringMetadataEntry\x12 \n\x18total_memory_usage_bytes\x18\t \x01(\x03\x12#\n\x1b\x61verage_cpu_load_percentage\x18\n \x01(\x02\x1a\x39\n\x17MonitoringMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb5\x02\n\x11PipelineAnalytics\x12\x13\n\x0bpipeline_id\x18\x01 \x01(\t\x12 \n\x18\x61verage_duration_seconds\x18\x02 \x01(\x02\x12\x1c\n\x14\x61verage_success_rate\x18\x03 \x01(\x02\x12&\n\x1e\x66requently_failed_stages_count\x18\x04 \x01(\x05\x12N\n\x14stage_failure_counts\x18\x05 \x03(\x0b\x32\x30.seigr.PipelineAnalytics.StageFailureCountsEntry\x12\x18\n\x10last_analyzed_at\x18\x06 \x01(\t\x1a\x39\n\x17StageFailureCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01*v\n\x0fOperationStatus\x12\x1e\n\x1aOPERATION_STATUS_UNDEFINED\x10\x00\x12\x15\n\x11OPERATION_SUCCESS\x10\x01\x12\x15\n\x11OPERATION_FAILURE\x10\x02\x12\x15\n\x11OPERATION_PENDING\x10\x03*y\n\x0cTriggerEvent\x12\x12\n\x0eON_DATA_CHANGE\x10\x00\x12\r\n\tON_ACCESS\x10\x01\x12\x18\n\x14ON_INTEGRITY_FAILURE\x10\x02\x12\x15\n\x11ON_CUSTOM_TRIGGER\x10\x03\x12\x15\n\x11ON_MANUAL_REQUEST\x10\x04*\x85\x02\n\x13PipelineStageStatus\x12#\n\x1fPIPELINE_STAGE_STATUS_UNDEFINED\x10\x00\x12\x1e\n\x1aPIPELINE_STAGE_INITIALIZED\x10\x01\x12\x1a\n\x16PIPELINE_STAGE_RUNNING\x10\x02\x12\x1c\n\x18PIPELINE_STAGE_COMPLETED\x10\x03\x12\x19\n\x15PIPELINE_STAGE_FAILED\x10\x04\x12\x1a\n\x16PIPELINE_STAGE_SKIPPED\x10\x05\x12\x1b\n\x17PIPELINE_STAGE_RETRYING\x10\x06\x12\x1b\n\x17PIPELINE_STAGE_CANCELED\x10\x07*\xb2\x01\n\x15\x45rrorRecoveryStrategy\x12\x16\n\x12RECOVERY_UNDEFINED\x10\x00\x12\x12\n\x0eRECOVERY_RETRY\x10\x01\x12\x11\n\rRECOVERY_SKIP\x10\x02\x12\x1f\n\x1bRECOVERY_TERMINATE_PIPELINE\x10\x03\x12\x1c\n\x18RECOVERY_ALERT_AND_PAUSE\x10\x04\x12\x1b\n\x17RECOVERY_ADAPTIVE_RETRY\x10\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'pipeline_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _PIPELINESTAGE_PARAMETERSENTRY._options = None
  _PIPELINESTAGE_PARAMETERSENTRY._serialized_options = b'8\001'
  _PIPELINESTAGE_EXECUTIONCONTEXTENTRY._options = None
  _PIPELINESTAGE_EXECUTIONCONTEXTENTRY._serialized_options = b'8\001'
  _PIPELINE_METADATAENTRY._options = None
  _PIPELINE_METADATAENTRY._serialized_options = b'8\001'
  _PIPELINECONFIG_CONFIGMETADATAENTRY._options = None
  _PIPELINECONFIG_CONFIGMETADATAENTRY._serialized_options = b'8\001'
  _PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY._options = None
  _PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY._serialized_options = b'8\001'
  _PIPELINEMONITORING_MONITORINGMETADATAENTRY._options = None
  _PIPELINEMONITORING_MONITORINGMETADATAENTRY._serialized_options = b'8\001'
  _PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY._options = None
  _PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY._serialized_options = b'8\001'
  _OPERATIONSTATUS._serialized_start=2766
  _OPERATIONSTATUS._serialized_end=2884
  _TRIGGEREVENT._serialized_start=2886
  _TRIGGEREVENT._serialized_end=3007
  _PIPELINESTAGESTATUS._serialized_start=3010
  _PIPELINESTAGESTATUS._serialized_end=3271
  _ERRORRECOVERYSTRATEGY._serialized_start=3274
  _ERRORRECOVERYSTRATEGY._serialized_end=3452
  _PIPELINESTAGE._serialized_start=26
  _PIPELINESTAGE._serialized_end=784
  _PIPELINESTAGE_PARAMETERSENTRY._serialized_start=678
  _PIPELINESTAGE_PARAMETERSENTRY._serialized_end=727
  _PIPELINESTAGE_EXECUTIONCONTEXTENTRY._serialized_start=729
  _PIPELINESTAGE_EXECUTIONCONTEXTENTRY._serialized_end=784
  _PIPELINE._serialized_start=787
  _PIPELINE._serialized_end=1150
  _PIPELINE_METADATAENTRY._serialized_start=1103
  _PIPELINE_METADATAENTRY._serialized_end=1150
  _PIPELINECONFIG._serialized_start=1153
  _PIPELINECONFIG._serialized_end=1507
  _PIPELINECONFIG_CONFIGMETADATAENTRY._serialized_start=1454
  _PIPELINECONFIG_CONFIGMETADATAENTRY._serialized_end=1507
  _PIPELINEEXECUTIONHISTORY._serialized_start=1510
  _PIPELINEEXECUTIONHISTORY._serialized_end=1675
  _PIPELINEEXECUTIONRECORD._serialized_start=1678
  _PIPELINEEXECUTIONRECORD._serialized_end=2018
  _PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY._serialized_start=1962
  _PIPELINEEXECUTIONRECORD_EXECUTIONMETADATAENTRY._serialized_end=2018
  _PIPELINEMONITORING._serialized_start=2021
  _PIPELINEMONITORING._serialized_end=2452
  _PIPELINEMONITORING_MONITORINGMETADATAENTRY._serialized_start=2395
  _PIPELINEMONITORING_MONITORINGMETADATAENTRY._serialized_end=2452
  _PIPELINEANALYTICS._serialized_start=2455
  _PIPELINEANALYTICS._serialized_end=2764
  _PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY._serialized_start=2707
  _PIPELINEANALYTICS_STAGEFAILURECOUNTSENTRY._serialized_end=2764
# @@protoc_insertion_point(module_scope)
