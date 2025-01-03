# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: ai_analysis.proto
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
    'ai_analysis.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11\x61i_analysis.proto\x12\x05seigr\"\xb8\x03\n\x0bModelConfig\x12\x10\n\x08model_id\x18\x01 \x01(\t\x12$\n\nmodel_type\x18\x02 \x01(\x0e\x32\x10.seigr.ModelType\x12\x12\n\nmodel_name\x18\x03 \x01(\t\x12\x0f\n\x07version\x18\x04 \x01(\x05\x12\x36\n\nparameters\x18\x05 \x03(\x0b\x32\".seigr.ModelConfig.ParametersEntry\x12\"\n\x1a\x65nable_real_time_inference\x18\x06 \x01(\x08\x12\x1d\n\x15retrain_interval_days\x18\x07 \x01(\x05\x12\x12\n\ncreated_by\x18\x08 \x01(\t\x12\x12\n\ncreated_at\x18\t \x01(\t\x12?\n\x0f\x63onfig_metadata\x18\n \x03(\x0b\x32&.seigr.ModelConfig.ConfigMetadataEntry\x1a\x31\n\x0fParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf8\x02\n\x0eModelExecution\x12\x14\n\x0c\x65xecution_id\x18\x01 \x01(\t\x12\x10\n\x08model_id\x18\x02 \x01(\t\x12$\n\nmodel_type\x18\x03 \x01(\x0e\x32\x10.seigr.ModelType\x12\x14\n\x0cinitiated_by\x18\x04 \x01(\t\x12\x14\n\x0c\x64\x61ta_sources\x18\x05 \x03(\t\x12\x17\n\x0f\x61sync_execution\x18\x06 \x01(\x08\x12\x1b\n\x13\x65xecution_timestamp\x18\x07 \x01(\t\x12H\n\x12\x65xecution_metadata\x18\x08 \x03(\x0b\x32,.seigr.ModelExecution.ExecutionMetadataEntry\x12\x32\n\x10\x65xpected_outcome\x18\t \x01(\x0e\x32\x18.seigr.PredictionOutcome\x1a\x38\n\x16\x45xecutionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc0\x02\n\x14ModelExecutionResult\x12\x14\n\x0c\x65xecution_id\x18\x01 \x01(\t\x12\x10\n\x08model_id\x18\x02 \x01(\t\x12\x0f\n\x07success\x18\x03 \x01(\x08\x12)\n\x07outcome\x18\x04 \x01(\x0e\x32\x18.seigr.PredictionOutcome\x12\x16\n\x0eresult_message\x18\x05 \x01(\t\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12H\n\x0fresult_metadata\x18\x07 \x03(\x0b\x32/.seigr.ModelExecutionResult.ResultMetadataEntry\x12\x18\n\x10\x63onfidence_score\x18\x08 \x01(\x01\x1a\x35\n\x13ResultMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x95\x02\n\x0cTrainingData\x12\x0f\n\x07\x64\x61ta_id\x18\x01 \x01(\t\x12\x14\n\x0c\x64\x61ta_sources\x18\x02 \x03(\t\x12<\n\rdata_metadata\x18\x03 \x03(\x0b\x32%.seigr.TrainingData.DataMetadataEntry\x12\x16\n\x0e\x63ollected_from\x18\x04 \x01(\t\x12\x1b\n\x13training_started_at\x18\x05 \x01(\t\x12\x1d\n\x15training_completed_at\x18\x06 \x01(\t\x12\x17\n\x0f\x64\x61taset_size_mb\x18\x07 \x01(\x01\x1a\x33\n\x11\x44\x61taMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf7\x02\n\x0fModelMonitoring\x12\x10\n\x08model_id\x18\x01 \x01(\t\x12\"\n\x06status\x18\x02 \x01(\x0e\x32\x12.seigr.ModelStatus\x12\x16\n\x0e\x61\x63\x63uracy_score\x18\x03 \x01(\x01\x12\x1a\n\x12\x61verage_latency_ms\x18\x04 \x01(\x01\x12\x1a\n\x12resource_usage_cpu\x18\x05 \x01(\x01\x12 \n\x18resource_usage_memory_mb\x18\x06 \x01(\x01\x12\x1e\n\x16predictions_per_minute\x18\x07 \x01(\x05\x12\x14\n\x0clast_updated\x18\x08 \x01(\t\x12K\n\x13monitoring_metadata\x18\t \x03(\x0b\x32..seigr.ModelMonitoring.MonitoringMetadataEntry\x1a\x39\n\x17MonitoringMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x95\x02\n\rModelAuditLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x10\n\x08model_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61\x63tion\x18\x03 \x01(\t\x12\x14\n\x0cperformed_by\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12;\n\x0clog_metadata\x18\x06 \x03(\x0b\x32%.seigr.ModelAuditLog.LogMetadataEntry\x12\x1d\n\x15\x63ompliance_issue_flag\x18\x07 \x01(\x08\x12\x19\n\x11\x63orrective_action\x18\x08 \x01(\t\x1a\x32\n\x10LogMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc3\x01\n\rModelResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x10\n\x08model_id\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x45\n\x11response_metadata\x18\x04 \x03(\x0b\x32*.seigr.ModelResponse.ResponseMetadataEntry\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"*\n\x16ModelMonitoringRequest\x12\x10\n\x08model_id\x18\x01 \x01(\t\"\xbf\x01\n\x11ModelAuditRequest\x12\x10\n\x08model_id\x18\x01 \x01(\t\x12\x18\n\x10time_range_start\x18\x02 \x01(\t\x12\x16\n\x0etime_range_end\x18\x03 \x01(\t\x12\x36\n\x07\x66ilters\x18\x04 \x03(\x0b\x32%.seigr.ModelAuditRequest.FiltersEntry\x1a.\n\x0c\x46iltersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"Y\n\x12ModelAuditResponse\x12\"\n\x04logs\x18\x01 \x03(\x0b\x32\x14.seigr.ModelAuditLog\x12\x0e\n\x06status\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t*\xc8\x01\n\tModelType\x12\x18\n\x14MODEL_TYPE_UNDEFINED\x10\x00\x12\x1b\n\x17MODEL_ANOMALY_DETECTION\x10\x01\x12\x1b\n\x17MODEL_DEMAND_PREDICTION\x10\x02\x12\x1b\n\x17MODEL_USAGE_FORECASTING\x10\x03\x12\x19\n\x15MODEL_RISK_ASSESSMENT\x10\x04\x12\x1d\n\x19MODEL_REPLICATION_SCALING\x10\x05\x12\x10\n\x0cMODEL_CUSTOM\x10\x06*\xad\x01\n\x0bModelStatus\x12\x1a\n\x16MODEL_STATUS_UNDEFINED\x10\x00\x12\x19\n\x15MODEL_STATUS_TRAINING\x10\x01\x12\x18\n\x14MODEL_STATUS_TRAINED\x10\x02\x12\x19\n\x15MODEL_STATUS_DEPLOYED\x10\x03\x12\x19\n\x15MODEL_STATUS_INACTIVE\x10\x04\x12\x17\n\x13MODEL_STATUS_FAILED\x10\x05*\xcb\x01\n\x11PredictionOutcome\x12\x15\n\x11OUTCOME_UNDEFINED\x10\x00\x12\x1c\n\x18OUTCOME_ANOMALY_DETECTED\x10\x01\x12\x12\n\x0eOUTCOME_NORMAL\x10\x02\x12\x17\n\x13OUTCOME_HIGH_DEMAND\x10\x03\x12\x16\n\x12OUTCOME_LOW_DEMAND\x10\x04\x12\x1b\n\x17OUTCOME_RISK_IDENTIFIED\x10\x05\x12\x1f\n\x1bOUTCOME_SCALING_RECOMMENDED\x10\x06\x32\xdc\x02\n\x11\x41IAnalysisService\x12\x37\n\x0b\x43reateModel\x12\x12.seigr.ModelConfig\x1a\x14.seigr.ModelResponse\x12\x42\n\x0c\x45xecuteModel\x12\x15.seigr.ModelExecution\x1a\x1b.seigr.ModelExecutionResult\x12\x39\n\x0cRetrainModel\x12\x13.seigr.TrainingData\x1a\x14.seigr.ModelResponse\x12\x45\n\x0cMonitorModel\x12\x1d.seigr.ModelMonitoringRequest\x1a\x16.seigr.ModelMonitoring\x12H\n\x11GetModelAuditLogs\x12\x18.seigr.ModelAuditRequest\x1a\x19.seigr.ModelAuditResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'ai_analysis_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_MODELCONFIG_PARAMETERSENTRY']._loaded_options = None
  _globals['_MODELCONFIG_PARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_MODELCONFIG_CONFIGMETADATAENTRY']._loaded_options = None
  _globals['_MODELCONFIG_CONFIGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELEXECUTION_EXECUTIONMETADATAENTRY']._loaded_options = None
  _globals['_MODELEXECUTION_EXECUTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELEXECUTIONRESULT_RESULTMETADATAENTRY']._loaded_options = None
  _globals['_MODELEXECUTIONRESULT_RESULTMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_TRAININGDATA_DATAMETADATAENTRY']._loaded_options = None
  _globals['_TRAININGDATA_DATAMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELMONITORING_MONITORINGMETADATAENTRY']._loaded_options = None
  _globals['_MODELMONITORING_MONITORINGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELAUDITLOG_LOGMETADATAENTRY']._loaded_options = None
  _globals['_MODELAUDITLOG_LOGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELRESPONSE_RESPONSEMETADATAENTRY']._loaded_options = None
  _globals['_MODELRESPONSE_RESPONSEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_MODELAUDITREQUEST_FILTERSENTRY']._loaded_options = None
  _globals['_MODELAUDITREQUEST_FILTERSENTRY']._serialized_options = b'8\001'
  _globals['_MODELTYPE']._serialized_start=2639
  _globals['_MODELTYPE']._serialized_end=2839
  _globals['_MODELSTATUS']._serialized_start=2842
  _globals['_MODELSTATUS']._serialized_end=3015
  _globals['_PREDICTIONOUTCOME']._serialized_start=3018
  _globals['_PREDICTIONOUTCOME']._serialized_end=3221
  _globals['_MODELCONFIG']._serialized_start=29
  _globals['_MODELCONFIG']._serialized_end=469
  _globals['_MODELCONFIG_PARAMETERSENTRY']._serialized_start=365
  _globals['_MODELCONFIG_PARAMETERSENTRY']._serialized_end=414
  _globals['_MODELCONFIG_CONFIGMETADATAENTRY']._serialized_start=416
  _globals['_MODELCONFIG_CONFIGMETADATAENTRY']._serialized_end=469
  _globals['_MODELEXECUTION']._serialized_start=472
  _globals['_MODELEXECUTION']._serialized_end=848
  _globals['_MODELEXECUTION_EXECUTIONMETADATAENTRY']._serialized_start=792
  _globals['_MODELEXECUTION_EXECUTIONMETADATAENTRY']._serialized_end=848
  _globals['_MODELEXECUTIONRESULT']._serialized_start=851
  _globals['_MODELEXECUTIONRESULT']._serialized_end=1171
  _globals['_MODELEXECUTIONRESULT_RESULTMETADATAENTRY']._serialized_start=1118
  _globals['_MODELEXECUTIONRESULT_RESULTMETADATAENTRY']._serialized_end=1171
  _globals['_TRAININGDATA']._serialized_start=1174
  _globals['_TRAININGDATA']._serialized_end=1451
  _globals['_TRAININGDATA_DATAMETADATAENTRY']._serialized_start=1400
  _globals['_TRAININGDATA_DATAMETADATAENTRY']._serialized_end=1451
  _globals['_MODELMONITORING']._serialized_start=1454
  _globals['_MODELMONITORING']._serialized_end=1829
  _globals['_MODELMONITORING_MONITORINGMETADATAENTRY']._serialized_start=1772
  _globals['_MODELMONITORING_MONITORINGMETADATAENTRY']._serialized_end=1829
  _globals['_MODELAUDITLOG']._serialized_start=1832
  _globals['_MODELAUDITLOG']._serialized_end=2109
  _globals['_MODELAUDITLOG_LOGMETADATAENTRY']._serialized_start=2059
  _globals['_MODELAUDITLOG_LOGMETADATAENTRY']._serialized_end=2109
  _globals['_MODELRESPONSE']._serialized_start=2112
  _globals['_MODELRESPONSE']._serialized_end=2307
  _globals['_MODELRESPONSE_RESPONSEMETADATAENTRY']._serialized_start=2252
  _globals['_MODELRESPONSE_RESPONSEMETADATAENTRY']._serialized_end=2307
  _globals['_MODELMONITORINGREQUEST']._serialized_start=2309
  _globals['_MODELMONITORINGREQUEST']._serialized_end=2351
  _globals['_MODELAUDITREQUEST']._serialized_start=2354
  _globals['_MODELAUDITREQUEST']._serialized_end=2545
  _globals['_MODELAUDITREQUEST_FILTERSENTRY']._serialized_start=2499
  _globals['_MODELAUDITREQUEST_FILTERSENTRY']._serialized_end=2545
  _globals['_MODELAUDITRESPONSE']._serialized_start=2547
  _globals['_MODELAUDITRESPONSE']._serialized_end=2636
  _globals['_AIANALYSISSERVICE']._serialized_start=3224
  _globals['_AIANALYSISSERVICE']._serialized_end=3572
# @@protoc_insertion_point(module_scope)
