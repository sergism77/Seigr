# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: reward_distribution.proto
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
    'reward_distribution.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x19reward_distribution.proto\x12\x19seigr.reward_distribution\"\xa8\x04\n\x06Reward\x12\x11\n\treward_id\x18\x01 \x01(\t\x12\x14\n\x0crecipient_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61mount\x18\x03 \x01(\x04\x12:\n\x0breward_type\x18\x04 \x01(\x0e\x32%.seigr.reward_distribution.RewardType\x12\x10\n\x08interval\x18\x05 \x01(\x04\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12\x12\n\nexpiration\x18\x07 \x01(\t\x12\x45\n\nconditions\x18\x08 \x03(\x0b\x32\x31.seigr.reward_distribution.Reward.ConditionsEntry\x12\x11\n\tissued_by\x18\t \x01(\t\x12\x19\n\x11\x65\x63o_friendly_flag\x18\n \x01(\x08\x12T\n\x12\x64ynamic_parameters\x18\x0b \x03(\x0b\x32\x38.seigr.reward_distribution.Reward.DynamicParametersEntry\x12\"\n\x1a\x61\x64\x61ptive_scaling_policy_id\x18\x0c \x01(\t\x12\x14\n\x0ctransferable\x18\r \x01(\x08\x1a\x31\n\x0f\x43onditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x38\n\x16\x44ynamicParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\"\xa5\x03\n\x12RedistributionPool\x12\x14\n\x0cpool_balance\x18\x01 \x01(\x04\x12\x37\n\x0creward_queue\x18\x02 \x03(\x0b\x32!.seigr.reward_distribution.Reward\x12\x18\n\x10senary_threshold\x18\x03 \x01(\x04\x12\x35\n\x06status\x18\x04 \x01(\x0e\x32%.seigr.reward_distribution.PoolStatus\x12`\n\x12\x64ynamic_thresholds\x18\x05 \x03(\x0b\x32\x44.seigr.reward_distribution.RedistributionPool.DynamicThresholdsEntry\x12\x18\n\x10\x65\x63o_reserve_fund\x18\x06 \x01(\x04\x12\x1b\n\x13last_distributed_at\x18\x07 \x01(\t\x12\x1c\n\x14replenishment_target\x18\x08 \x01(\x04\x1a\x38\n\x16\x44ynamicThresholdsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\"\x96\x03\n\x13RewardScalingConfig\x12\x16\n\x0escaling_factor\x18\x01 \x01(\x01\x12\x1b\n\x13\x61\x64justment_interval\x18\x02 \x01(\x04\x12\x1a\n\x12min_scaling_factor\x18\x03 \x01(\x01\x12\x1a\n\x12max_scaling_factor\x18\x04 \x01(\x01\x12\x1b\n\x13\x65\x63o_priority_weight\x18\x05 \x01(\x01\x12\x1e\n\x16max_distribution_limit\x18\x06 \x01(\x04\x12 \n\x18\x61\x64\x61ptive_scaling_enabled\x18\x07 \x01(\x08\x12\x1c\n\x14\x66\x61irness_coefficient\x18\x08 \x01(\x01\x12]\n\x10scaling_metadata\x18\t \x03(\x0b\x32\x43.seigr.reward_distribution.RewardScalingConfig.ScalingMetadataEntry\x1a\x36\n\x14ScalingMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xce\x02\n\x15\x41llocateRewardRequest\x12\x14\n\x0crecipient_id\x18\x01 \x01(\t\x12:\n\x0breward_type\x18\x02 \x01(\x0e\x32%.seigr.reward_distribution.RewardType\x12\x0e\n\x06\x61mount\x18\x03 \x01(\x04\x12i\n\x15\x61\x64\x64itional_conditions\x18\x04 \x03(\x0b\x32J.seigr.reward_distribution.AllocateRewardRequest.AdditionalConditionsEntry\x12\x15\n\reco_incentive\x18\x05 \x01(\x08\x12\x14\n\x0ctransferable\x18\x06 \x01(\x08\x1a;\n\x19\x41\x64\x64itionalConditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"M\n\x16\x41llocateRewardResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x11\n\treward_id\x18\x03 \x01(\t\"t\n\x15\x44istributePoolRequest\x12\x18\n\x10senary_threshold\x18\x01 \x01(\x04\x12 \n\x18override_inactive_status\x18\x02 \x01(\x08\x12\x1f\n\x17prioritize_eco_friendly\x18\x03 \x01(\x08\"\x95\x02\n\x16\x44istributePoolResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x1a\n\x12\x64istributed_amount\x18\x02 \x01(\x04\x12\x0f\n\x07message\x18\x03 \x01(\t\x12y\n\x1dreward_distribution_breakdown\x18\x04 \x03(\x0b\x32R.seigr.reward_distribution.DistributePoolResponse.RewardDistributionBreakdownEntry\x1a\x42\n RewardDistributionBreakdownEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x04:\x02\x38\x01\"D\n\x14ReplenishPoolRequest\x12\x0e\n\x06\x61mount\x18\x01 \x01(\x04\x12\x1c\n\x14replenishment_source\x18\x02 \x01(\t\"N\n\x15ReplenishPoolResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x13\n\x0bnew_balance\x18\x02 \x01(\x04\x12\x0f\n\x07message\x18\x03 \x01(\t\"q\n\x17GetRewardHistoryRequest\x12\x14\n\x0crecipient_id\x18\x01 \x01(\t\x12\r\n\x05limit\x18\x02 \x01(\r\x12\x17\n\x0finclude_expired\x18\x03 \x01(\x08\x12\x18\n\x10only_eco_rewards\x18\x04 \x01(\x08\"d\n\x18GetRewardHistoryResponse\x12\x14\n\x0crecipient_id\x18\x01 \x01(\t\x12\x32\n\x07rewards\x18\x02 \x03(\x0b\x32!.seigr.reward_distribution.Reward\"\xcc\x01\n\x1aUpdateScalingConfigRequest\x12\x1a\n\x12new_scaling_factor\x18\x01 \x01(\x01\x12\x1f\n\x17new_adjustment_interval\x18\x02 \x01(\x04\x12\x1a\n\x12min_scaling_factor\x18\x03 \x01(\x01\x12\x1a\n\x12max_scaling_factor\x18\x04 \x01(\x01\x12\x1b\n\x13\x65\x63o_priority_weight\x18\x05 \x01(\x01\x12\x1c\n\x14\x66\x61irness_coefficient\x18\x06 \x01(\x01\"?\n\x1bUpdateScalingConfigResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"F\n\x10\x45\x63oReportRequest\x12\x0e\n\x06period\x18\x01 \x01(\t\x12\"\n\x1ainclude_detailed_breakdown\x18\x02 \x01(\x08\"\xa5\x02\n\x11\x45\x63oReportResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x66\n\x16\x65\x63o_incentives_summary\x18\x03 \x03(\x0b\x32\x46.seigr.reward_distribution.EcoReportResponse.EcoIncentivesSummaryEntry\x12#\n\x1btotal_eco_funds_distributed\x18\x04 \x01(\x01\x12$\n\x1cnetwork_sustainability_score\x18\x05 \x01(\x01\x1a;\n\x19\x45\x63oIncentivesSummaryEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01*\x9c\x02\n\nRewardType\x12\x19\n\x15REWARD_TYPE_UNDEFINED\x10\x00\x12\x1c\n\x18REWARD_TYPE_CONNECTIVITY\x10\x01\x12$\n REWARD_TYPE_CONTENT_CONTRIBUTION\x10\x02\x12$\n REWARD_TYPE_VOTING_PARTICIPATION\x10\x03\x12#\n\x1fREWARD_TYPE_RESOURCE_EFFICIENCY\x10\x04\x12\"\n\x1eREWARD_TYPE_COLLABORATIVE_TASK\x10\x05\x12\x1e\n\x1aREWARD_TYPE_SUSTAINABILITY\x10\x06\x12 \n\x1cREWARD_TYPE_ADAPTIVE_SUPPORT\x10\x07*\xaf\x01\n\nPoolStatus\x12\x19\n\x15POOL_STATUS_UNDEFINED\x10\x00\x12\x16\n\x12POOL_STATUS_ACTIVE\x10\x01\x12\x18\n\x14POOL_STATUS_INACTIVE\x10\x02\x12\x1c\n\x18POOL_STATUS_DISTRIBUTING\x10\x03\x12\x18\n\x14POOL_STATUS_DEPLETED\x10\x04\x12\x1c\n\x18POOL_STATUS_REPLENISHING\x10\x05\x32\xf1\x05\n\x19RewardDistributionService\x12u\n\x0e\x41llocateReward\x12\x30.seigr.reward_distribution.AllocateRewardRequest\x1a\x31.seigr.reward_distribution.AllocateRewardResponse\x12u\n\x0e\x44istributePool\x12\x30.seigr.reward_distribution.DistributePoolRequest\x1a\x31.seigr.reward_distribution.DistributePoolResponse\x12{\n\x10GetRewardHistory\x12\x32.seigr.reward_distribution.GetRewardHistoryRequest\x1a\x33.seigr.reward_distribution.GetRewardHistoryResponse\x12\x84\x01\n\x13UpdateScalingConfig\x12\x35.seigr.reward_distribution.UpdateScalingConfigRequest\x1a\x36.seigr.reward_distribution.UpdateScalingConfigResponse\x12n\n\x11GenerateEcoReport\x12+.seigr.reward_distribution.EcoReportRequest\x1a,.seigr.reward_distribution.EcoReportResponse\x12r\n\rReplenishPool\x12/.seigr.reward_distribution.ReplenishPoolRequest\x1a\x30.seigr.reward_distribution.ReplenishPoolResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'reward_distribution_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_REWARD_CONDITIONSENTRY']._loaded_options = None
  _globals['_REWARD_CONDITIONSENTRY']._serialized_options = b'8\001'
  _globals['_REWARD_DYNAMICPARAMETERSENTRY']._loaded_options = None
  _globals['_REWARD_DYNAMICPARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_REDISTRIBUTIONPOOL_DYNAMICTHRESHOLDSENTRY']._loaded_options = None
  _globals['_REDISTRIBUTIONPOOL_DYNAMICTHRESHOLDSENTRY']._serialized_options = b'8\001'
  _globals['_REWARDSCALINGCONFIG_SCALINGMETADATAENTRY']._loaded_options = None
  _globals['_REWARDSCALINGCONFIG_SCALINGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_ALLOCATEREWARDREQUEST_ADDITIONALCONDITIONSENTRY']._loaded_options = None
  _globals['_ALLOCATEREWARDREQUEST_ADDITIONALCONDITIONSENTRY']._serialized_options = b'8\001'
  _globals['_DISTRIBUTEPOOLRESPONSE_REWARDDISTRIBUTIONBREAKDOWNENTRY']._loaded_options = None
  _globals['_DISTRIBUTEPOOLRESPONSE_REWARDDISTRIBUTIONBREAKDOWNENTRY']._serialized_options = b'8\001'
  _globals['_ECOREPORTRESPONSE_ECOINCENTIVESSUMMARYENTRY']._loaded_options = None
  _globals['_ECOREPORTRESPONSE_ECOINCENTIVESSUMMARYENTRY']._serialized_options = b'8\001'
  _globals['_REWARDTYPE']._serialized_start=3266
  _globals['_REWARDTYPE']._serialized_end=3550
  _globals['_POOLSTATUS']._serialized_start=3553
  _globals['_POOLSTATUS']._serialized_end=3728
  _globals['_REWARD']._serialized_start=57
  _globals['_REWARD']._serialized_end=609
  _globals['_REWARD_CONDITIONSENTRY']._serialized_start=502
  _globals['_REWARD_CONDITIONSENTRY']._serialized_end=551
  _globals['_REWARD_DYNAMICPARAMETERSENTRY']._serialized_start=553
  _globals['_REWARD_DYNAMICPARAMETERSENTRY']._serialized_end=609
  _globals['_REDISTRIBUTIONPOOL']._serialized_start=612
  _globals['_REDISTRIBUTIONPOOL']._serialized_end=1033
  _globals['_REDISTRIBUTIONPOOL_DYNAMICTHRESHOLDSENTRY']._serialized_start=977
  _globals['_REDISTRIBUTIONPOOL_DYNAMICTHRESHOLDSENTRY']._serialized_end=1033
  _globals['_REWARDSCALINGCONFIG']._serialized_start=1036
  _globals['_REWARDSCALINGCONFIG']._serialized_end=1442
  _globals['_REWARDSCALINGCONFIG_SCALINGMETADATAENTRY']._serialized_start=1388
  _globals['_REWARDSCALINGCONFIG_SCALINGMETADATAENTRY']._serialized_end=1442
  _globals['_ALLOCATEREWARDREQUEST']._serialized_start=1445
  _globals['_ALLOCATEREWARDREQUEST']._serialized_end=1779
  _globals['_ALLOCATEREWARDREQUEST_ADDITIONALCONDITIONSENTRY']._serialized_start=1720
  _globals['_ALLOCATEREWARDREQUEST_ADDITIONALCONDITIONSENTRY']._serialized_end=1779
  _globals['_ALLOCATEREWARDRESPONSE']._serialized_start=1781
  _globals['_ALLOCATEREWARDRESPONSE']._serialized_end=1858
  _globals['_DISTRIBUTEPOOLREQUEST']._serialized_start=1860
  _globals['_DISTRIBUTEPOOLREQUEST']._serialized_end=1976
  _globals['_DISTRIBUTEPOOLRESPONSE']._serialized_start=1979
  _globals['_DISTRIBUTEPOOLRESPONSE']._serialized_end=2256
  _globals['_DISTRIBUTEPOOLRESPONSE_REWARDDISTRIBUTIONBREAKDOWNENTRY']._serialized_start=2190
  _globals['_DISTRIBUTEPOOLRESPONSE_REWARDDISTRIBUTIONBREAKDOWNENTRY']._serialized_end=2256
  _globals['_REPLENISHPOOLREQUEST']._serialized_start=2258
  _globals['_REPLENISHPOOLREQUEST']._serialized_end=2326
  _globals['_REPLENISHPOOLRESPONSE']._serialized_start=2328
  _globals['_REPLENISHPOOLRESPONSE']._serialized_end=2406
  _globals['_GETREWARDHISTORYREQUEST']._serialized_start=2408
  _globals['_GETREWARDHISTORYREQUEST']._serialized_end=2521
  _globals['_GETREWARDHISTORYRESPONSE']._serialized_start=2523
  _globals['_GETREWARDHISTORYRESPONSE']._serialized_end=2623
  _globals['_UPDATESCALINGCONFIGREQUEST']._serialized_start=2626
  _globals['_UPDATESCALINGCONFIGREQUEST']._serialized_end=2830
  _globals['_UPDATESCALINGCONFIGRESPONSE']._serialized_start=2832
  _globals['_UPDATESCALINGCONFIGRESPONSE']._serialized_end=2895
  _globals['_ECOREPORTREQUEST']._serialized_start=2897
  _globals['_ECOREPORTREQUEST']._serialized_end=2967
  _globals['_ECOREPORTRESPONSE']._serialized_start=2970
  _globals['_ECOREPORTRESPONSE']._serialized_end=3263
  _globals['_ECOREPORTRESPONSE_ECOINCENTIVESSUMMARYENTRY']._serialized_start=3204
  _globals['_ECOREPORTRESPONSE_ECOINCENTIVESSUMMARYENTRY']._serialized_end=3263
  _globals['_REWARDDISTRIBUTIONSERVICE']._serialized_start=3731
  _globals['_REWARDDISTRIBUTIONSERVICE']._serialized_end=4484
# @@protoc_insertion_point(module_scope)
