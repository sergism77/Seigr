# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: resource_management.proto
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
    'resource_management.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x19resource_management.proto\x12\x05seigr\"\xbd\x03\n\rResourceUsage\x12!\n\x04type\x18\x01 \x01(\x0e\x32\x13.seigr.ResourceType\x12\x18\n\x10usage_percentage\x18\x02 \x01(\x01\x12\x16\n\x0e\x61\x62solute_usage\x18\x03 \x01(\x01\x12\x0c\n\x04unit\x18\x04 \x01(\t\x12\x11\n\thyphen_id\x18\x05 \x01(\t\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12#\n\x05state\x18\x07 \x01(\x0e\x32\x14.seigr.ResourceState\x12?\n\x0eusage_metadata\x18\x08 \x03(\x0b\x32\'.seigr.ResourceUsage.UsageMetadataEntry\x12\x16\n\x0e\x61pplication_id\x18\t \x01(\t\x12\x13\n\x0btemperature\x18\n \x01(\x01\x12!\n\x19resource_efficiency_score\x18\x0b \x01(\x01\x12\x19\n\x11power_consumption\x18\x0c \x01(\x01\x12\x1c\n\x14sustainable_use_flag\x18\r \x01(\x08\x1a\x34\n\x12UsageMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xbb\x02\n\x0eResourceLimits\x12!\n\x04type\x18\x01 \x01(\x0e\x32\x13.seigr.ResourceType\x12\x19\n\x11warning_threshold\x18\x02 \x01(\x01\x12\x1a\n\x12\x63ritical_threshold\x18\x03 \x01(\x01\x12\x14\n\x0c\x61\x62solute_max\x18\x04 \x01(\x01\x12\x0c\n\x04unit\x18\x05 \x01(\t\x12\x16\n\x0e\x65nforce_limits\x18\x06 \x01(\x08\x12\x1a\n\x12\x65scalation_contact\x18\x07 \x01(\t\x12\'\n\x1fmax_continuous_overload_seconds\x18\x08 \x01(\x05\x12\x19\n\x11\x61uto_scale_action\x18\t \x01(\t\x12\x18\n\x10usage_decay_rate\x18\n \x01(\x01\x12\x19\n\x11sustainable_limit\x18\x0b \x01(\x01\"\xda\x04\n\x15ResourceMonitorConfig\x12\x1e\n\x16\x63heck_interval_seconds\x18\x01 \x01(\x05\x12.\n\x0fresource_limits\x18\x02 \x03(\x0b\x32\x15.seigr.ResourceLimits\x12\x17\n\x0f\x65nable_alerting\x18\x03 \x01(\x08\x12I\n\x0f\x63onfig_metadata\x18\x04 \x03(\x0b\x32\x30.seigr.ResourceMonitorConfig.ConfigMetadataEntry\x12\x16\n\x0e\x61lert_protocol\x18\x05 \x01(\t\x12\x1c\n\x14grace_period_seconds\x18\x06 \x01(\x05\x12\x1c\n\x14\x61uto_scale_threshold\x18\x07 \x01(\x05\x12T\n\x15\x61lert_severity_levels\x18\x08 \x03(\x0b\x32\x35.seigr.ResourceMonitorConfig.AlertSeverityLevelsEntry\x12\x1d\n\x15\x61lert_frequency_limit\x18\t \x01(\x05\x12 \n\x18load_balancing_threshold\x18\n \x01(\x01\x12/\n\'resource_efficiency_adjustment_interval\x18\x0b \x01(\x05\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a:\n\x18\x41lertSeverityLevelsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\"\xfc\x02\n\x14ResourceUsageSummary\x12!\n\x04type\x18\x01 \x01(\x0e\x32\x13.seigr.ResourceType\x12\x11\n\thyphen_id\x18\x02 \x01(\t\x12\x15\n\raverage_usage\x18\x03 \x01(\x01\x12\x12\n\npeak_usage\x18\x04 \x01(\x01\x12\x15\n\rminimum_usage\x18\x05 \x01(\x01\x12 \n\x18usage_standard_deviation\x18\x06 \x01(\x01\x12\x16\n\x0esummary_period\x18\x07 \x01(\t\x12\x1e\n\x16threshold_exceed_count\x18\x08 \x01(\x05\x12\x15\n\rcost_estimate\x18\t \x01(\x01\x12\x1c\n\x14time_above_threshold\x18\n \x01(\x05\x12\x1c\n\x14\x65\x66\x66iciency_score_avg\x18\x0b \x01(\x01\x12\x1d\n\x15power_consumption_avg\x18\x0c \x01(\x01\x12 \n\x18sustainability_compliant\x18\r \x01(\x08\"\x85\x06\n\x15\x43lusterResourceStatus\x12\x12\n\ncluster_id\x18\x01 \x01(\t\x12\x35\n\x10hyphen_summaries\x18\x02 \x03(\x0b\x32\x1b.seigr.ResourceUsageSummary\x12T\n\x15\x63luster_average_usage\x18\x03 \x03(\x0b\x32\x35.seigr.ClusterResourceStatus.ClusterAverageUsageEntry\x12N\n\x12\x63luster_peak_usage\x18\x04 \x03(\x0b\x32\x32.seigr.ClusterResourceStatus.ClusterPeakUsageEntry\x12\x14\n\x0clast_updated\x18\x05 \x01(\t\x12\x15\n\rhealth_status\x18\x06 \x01(\t\x12 \n\x18overloaded_hyphens_count\x18\x07 \x01(\x05\x12\x1c\n\x14recovery_action_plan\x18\x08 \x01(\t\x12!\n\x19\x63luster_utilization_score\x18\t \x01(\x01\x12<\n\x08metadata\x18\n \x03(\x0b\x32*.seigr.ClusterResourceStatus.MetadataEntry\x12\x1f\n\x17load_distribution_score\x18\x0b \x01(\x01\x12\x1d\n\x15\x61lert_escalation_path\x18\x0c \x01(\t\x12&\n\x1esustainability_compliance_rate\x18\r \x01(\x01\x12\x1f\n\x17\x61\x64\x61ptive_scaling_events\x18\x0e \x01(\x05\x1a:\n\x18\x43lusterAverageUsageEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a\x37\n\x15\x43lusterPeakUsageEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe7\x02\n\x16ResourceDemandForecast\x12!\n\x04type\x18\x01 \x01(\x0e\x32\x13.seigr.ResourceType\x12\x12\n\ncluster_id\x18\x02 \x01(\t\x12\x17\n\x0f\x66orecast_period\x18\x03 \x01(\t\x12\x1c\n\x14projected_peak_usage\x18\x04 \x01(\x01\x12\x1f\n\x17projected_average_usage\x18\x05 \x01(\x01\x12\x18\n\x10\x63onfidence_level\x18\x06 \x01(\x01\x12\x1b\n\x13\x66orecast_created_at\x18\x07 \x01(\t\x12N\n\x11\x66orecast_metadata\x18\x08 \x03(\x0b\x32\x33.seigr.ResourceDemandForecast.ForecastMetadataEntry\x1a\x37\n\x15\x46orecastMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x95\x03\n\x14ResourceDistribution\x12\x17\n\x0f\x64istribution_id\x18\x01 \x01(\t\x12!\n\x04type\x18\x02 \x01(\x0e\x32\x13.seigr.ResourceType\x12\x19\n\x11source_cluster_id\x18\x03 \x01(\t\x12\x1a\n\x12target_cluster_ids\x18\x04 \x03(\t\x12\x1b\n\x13max_latency_allowed\x18\x05 \x01(\x01\x12 \n\x18min_efficiency_threshold\x18\x06 \x01(\x01\x12\x1d\n\x15\x64istribution_strategy\x18\x07 \x01(\t\x12T\n\x15\x64istribution_metadata\x18\x08 \x03(\x0b\x32\x35.seigr.ResourceDistribution.DistributionMetadataEntry\x12\x19\n\x11\x65nable_encryption\x18\t \x01(\x08\x1a;\n\x19\x44istributionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xb8\x01\n\x0cResourceType\x12\x16\n\x12RESOURCE_UNDEFINED\x10\x00\x12\x10\n\x0cRESOURCE_CPU\x10\x01\x12\x13\n\x0fRESOURCE_MEMORY\x10\x02\x12\x14\n\x10RESOURCE_DISK_IO\x10\x03\x12\x16\n\x12RESOURCE_BANDWIDTH\x10\x04\x12\x10\n\x0cRESOURCE_GPU\x10\x05\x12\x14\n\x10RESOURCE_STORAGE\x10\x06\x12\x13\n\x0fRESOURCE_ENERGY\x10\x07*\xbc\x01\n\rResourceState\x12\x1c\n\x18RESOURCE_STATE_UNDEFINED\x10\x00\x12\x1a\n\x16RESOURCE_STATE_OPTIMAL\x10\x01\x12\x19\n\x15RESOURCE_STATE_NORMAL\x10\x02\x12\x1a\n\x16RESOURCE_STATE_WARNING\x10\x03\x12\x1b\n\x17RESOURCE_STATE_CRITICAL\x10\x04\x12\x1d\n\x19RESOURCE_STATE_OVERLOADED\x10\x05\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'resource_management_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_RESOURCEUSAGE_USAGEMETADATAENTRY']._loaded_options = None
  _globals['_RESOURCEUSAGE_USAGEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_RESOURCEMONITORCONFIG_CONFIGMETADATAENTRY']._loaded_options = None
  _globals['_RESOURCEMONITORCONFIG_CONFIGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_RESOURCEMONITORCONFIG_ALERTSEVERITYLEVELSENTRY']._loaded_options = None
  _globals['_RESOURCEMONITORCONFIG_ALERTSEVERITYLEVELSENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERAVERAGEUSAGEENTRY']._loaded_options = None
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERAVERAGEUSAGEENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERPEAKUSAGEENTRY']._loaded_options = None
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERPEAKUSAGEENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESOURCESTATUS_METADATAENTRY']._loaded_options = None
  _globals['_CLUSTERRESOURCESTATUS_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_RESOURCEDEMANDFORECAST_FORECASTMETADATAENTRY']._loaded_options = None
  _globals['_RESOURCEDEMANDFORECAST_FORECASTMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_RESOURCEDISTRIBUTION_DISTRIBUTIONMETADATAENTRY']._loaded_options = None
  _globals['_RESOURCEDISTRIBUTION_DISTRIBUTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_RESOURCETYPE']._serialized_start=3337
  _globals['_RESOURCETYPE']._serialized_end=3521
  _globals['_RESOURCESTATE']._serialized_start=3524
  _globals['_RESOURCESTATE']._serialized_end=3712
  _globals['_RESOURCEUSAGE']._serialized_start=37
  _globals['_RESOURCEUSAGE']._serialized_end=482
  _globals['_RESOURCEUSAGE_USAGEMETADATAENTRY']._serialized_start=430
  _globals['_RESOURCEUSAGE_USAGEMETADATAENTRY']._serialized_end=482
  _globals['_RESOURCELIMITS']._serialized_start=485
  _globals['_RESOURCELIMITS']._serialized_end=800
  _globals['_RESOURCEMONITORCONFIG']._serialized_start=803
  _globals['_RESOURCEMONITORCONFIG']._serialized_end=1405
  _globals['_RESOURCEMONITORCONFIG_CONFIGMETADATAENTRY']._serialized_start=1292
  _globals['_RESOURCEMONITORCONFIG_CONFIGMETADATAENTRY']._serialized_end=1345
  _globals['_RESOURCEMONITORCONFIG_ALERTSEVERITYLEVELSENTRY']._serialized_start=1347
  _globals['_RESOURCEMONITORCONFIG_ALERTSEVERITYLEVELSENTRY']._serialized_end=1405
  _globals['_RESOURCEUSAGESUMMARY']._serialized_start=1408
  _globals['_RESOURCEUSAGESUMMARY']._serialized_end=1788
  _globals['_CLUSTERRESOURCESTATUS']._serialized_start=1791
  _globals['_CLUSTERRESOURCESTATUS']._serialized_end=2564
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERAVERAGEUSAGEENTRY']._serialized_start=2400
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERAVERAGEUSAGEENTRY']._serialized_end=2458
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERPEAKUSAGEENTRY']._serialized_start=2460
  _globals['_CLUSTERRESOURCESTATUS_CLUSTERPEAKUSAGEENTRY']._serialized_end=2515
  _globals['_CLUSTERRESOURCESTATUS_METADATAENTRY']._serialized_start=2517
  _globals['_CLUSTERRESOURCESTATUS_METADATAENTRY']._serialized_end=2564
  _globals['_RESOURCEDEMANDFORECAST']._serialized_start=2567
  _globals['_RESOURCEDEMANDFORECAST']._serialized_end=2926
  _globals['_RESOURCEDEMANDFORECAST_FORECASTMETADATAENTRY']._serialized_start=2871
  _globals['_RESOURCEDEMANDFORECAST_FORECASTMETADATAENTRY']._serialized_end=2926
  _globals['_RESOURCEDISTRIBUTION']._serialized_start=2929
  _globals['_RESOURCEDISTRIBUTION']._serialized_end=3334
  _globals['_RESOURCEDISTRIBUTION_DISTRIBUTIONMETADATAENTRY']._serialized_start=3275
  _globals['_RESOURCEDISTRIBUTION_DISTRIBUTIONMETADATAENTRY']._serialized_end=3334
# @@protoc_insertion_point(module_scope)
