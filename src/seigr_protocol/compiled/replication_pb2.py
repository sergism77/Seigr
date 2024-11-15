# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: replication.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_requests_pb2 as common__requests__pb2
import event_pb2 as event__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11replication.proto\x12\x05seigr\x1a\x15\x63ommon_requests.proto\x1a\x0b\x65vent.proto\"\x93\x04\n\x11ReplicationConfig\x12\x1a\n\x12replication_factor\x18\x01 \x01(\x05\x12\x1e\n\x16min_replication_factor\x18\x02 \x01(\x05\x12\x1e\n\x16max_replication_factor\x18\x03 \x01(\x05\x12$\n\x1c\x61\x64\x61ptive_replication_enabled\x18\x04 \x01(\x08\x12\x34\n\x10\x64\x65\x66\x61ult_strategy\x18\x05 \x01(\x0e\x32\x1a.seigr.ReplicationStrategy\x12\x16\n\x0e\x63onfig_version\x18\x06 \x01(\t\x12\x38\n\x08metadata\x18\x07 \x03(\x0b\x32&.seigr.ReplicationConfig.MetadataEntry\x12\"\n\x1a\x61\x64\x61ptive_scaling_threshold\x18\x08 \x01(\x05\x12\x18\n\x10\x66\x61ilover_enabled\x18\t \x01(\x08\x12\"\n\x1a\x64ynamic_redundancy_scaling\x18\n \x01(\x08\x12!\n\x19load_balanced_replication\x18\x0b \x01(\x08\x12 \n\x18\x61uto_priority_adjustment\x18\x0c \x01(\x08\x12\x1c\n\x14redundancy_policy_id\x18\r \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf5\x03\n\x11ReplicationStatus\x12\x12\n\nsegment_id\x18\x01 \x01(\t\x12!\n\x19\x63urrent_replication_count\x18\x02 \x01(\x05\x12 \n\x18target_replication_count\x18\x03 \x01(\x05\x12\x1a\n\x12replica_hyphen_ids\x18\x04 \x03(\t\x12\x1d\n\x15replication_completed\x18\x05 \x01(\x08\x12,\n\x08priority\x18\x06 \x01(\x0e\x32\x1a.seigr.ReplicationPriority\x12\x14\n\x0clast_checked\x18\x07 \x01(\t\x12\x38\n\x08metadata\x18\x08 \x03(\x0b\x32&.seigr.ReplicationStatus.MetadataEntry\x12\x1a\n\x12\x66\x61ilover_target_id\x18\t \x01(\t\x12!\n\x19\x65stimated_completion_time\x18\n \x01(\x05\x12\'\n\x1freplication_speed_bytes_per_sec\x18\x0b \x01(\x03\x12\x1c\n\x14replication_progress\x18\x0c \x01(\x02\x12\x17\n\x0fis_synchronized\x18\r \x01(\x08\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xee\x02\n\x13ReplicationEventLog\x12\x10\n\x08\x65vent_id\x18\x01 \x01(\t\x12\x12\n\nsegment_id\x18\x02 \x01(\t\x12\x0e\n\x06\x61\x63tion\x18\x03 \x01(\t\x12\x14\n\x0cinitiated_by\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12\x0e\n\x06status\x18\x06 \x01(\t\x12\x38\n\x07\x64\x65tails\x18\x07 \x03(\x0b\x32\'.seigr.ReplicationEventLog.DetailsEntry\x12\x17\n\x0f\x66\x61ilover_status\x18\x08 \x01(\t\x12\x16\n\x0einitiator_type\x18\t \x01(\t\x12\x19\n\x11retries_attempted\x18\n \x01(\x05\x12\x18\n\x10\x65scalation_level\x18\x0b \x01(\t\x12\x18\n\x10resolution_notes\x18\x0c \x01(\t\x1a.\n\x0c\x44\x65tailsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc2\x04\n\x11RedundancyManager\x12\x1c\n\x14min_redundancy_level\x18\x01 \x01(\x05\x12\x1c\n\x14max_redundancy_level\x18\x02 \x01(\x05\x12G\n\x10segment_priority\x18\x03 \x03(\x0b\x32-.seigr.RedundancyManager.SegmentPriorityEntry\x12\x1e\n\x16high_priority_segments\x18\x04 \x03(\t\x12\x19\n\x11\x63ritical_segments\x18\x05 \x03(\t\x12M\n\x13redundancy_metadata\x18\x06 \x03(\x0b\x32\x30.seigr.RedundancyManager.RedundancyMetadataEntry\x12 \n\x18\x66\x61ilover_timeout_seconds\x18\x07 \x01(\x05\x12\x1b\n\x13\x61\x64\x61ptive_redundancy\x18\x08 \x01(\x08\x12%\n\x1d\x61\x64\x61ptive_redundancy_policy_id\x18\t \x01(\t\x12)\n!cross_cluster_replication_enabled\x18\n \x01(\x08\x1aR\n\x14SegmentPriorityEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12)\n\x05value\x18\x02 \x01(\x0e\x32\x1a.seigr.ReplicationPriority:\x02\x38\x01\x1a\x39\n\x17RedundancyMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x84\x05\n\x15ReplicationEscalation\x12\x15\n\rescalation_id\x18\x01 \x01(\t\x12\x12\n\nsegment_id\x18\x02 \x01(\t\x12,\n\x08priority\x18\x03 \x01(\x0e\x32\x1a.seigr.ReplicationPriority\x12\x14\n\x0c\x65scalated_at\x18\x04 \x01(\t\x12\x0e\n\x06reason\x18\x05 \x01(\t\x12\x18\n\x10\x61lert_recipients\x18\x06 \x03(\t\x12\'\n\x1fimmediate_replication_triggered\x18\x07 \x01(\x08\x12<\n\x08metadata\x18\x08 \x03(\x0b\x32*.seigr.ReplicationEscalation.MetadataEntry\x12M\n\x11\x61lert_preferences\x18\t \x03(\x0b\x32\x32.seigr.ReplicationEscalation.AlertPreferencesEntry\x12\x30\n\x10\x65scalation_level\x18\n \x01(\x0e\x32\x16.seigr.EscalationLevel\x12\x19\n\x11\x65scalation_status\x18\x0b \x01(\t\x12\'\n\x1f\x65scalation_resolution_timestamp\x18\x0c \x01(\t\x12\x19\n\x11\x66\x61llback_strategy\x18\r \x01(\t\x12!\n\x19replication_delay_penalty\x18\x0e \x01(\x05\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x37\n\x15\x41lertPreferencesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x85\x06\n\x12ReplicationSummary\x12\x12\n\nsummary_id\x18\x01 \x01(\t\x12!\n\x19total_segments_replicated\x18\x02 \x01(\x05\x12\"\n\x1ahigh_priority_replications\x18\x03 \x01(\x05\x12\x1b\n\x13\x66\x61iled_replications\x18\x04 \x01(\x05\x12\x1c\n\x14ongoing_replications\x18\x05 \x01(\x05\x12\x14\n\x0cgenerated_at\x18\x06 \x01(\t\x12H\n\x10segment_statuses\x18\x07 \x03(\x0b\x32..seigr.ReplicationSummary.SegmentStatusesEntry\x12H\n\x10summary_metadata\x18\x08 \x03(\x0b\x32..seigr.ReplicationSummary.SummaryMetadataEntry\x12 \n\x18\x61verage_replication_time\x18\t \x01(\x02\x12#\n\x1btotal_data_replicated_bytes\x18\n \x01(\x03\x12\x1c\n\x14synchronization_rate\x18\x0b \x01(\x02\x12J\n\x11\x65scalation_counts\x18\x0c \x03(\x0b\x32/.seigr.ReplicationSummary.EscalationCountsEntry\x12\x15\n\rfailover_rate\x18\r \x01(\x02\x12$\n\x1credundancy_satisfaction_rate\x18\x0e \x01(\x02\x1aP\n\x14SegmentStatusesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\'\n\x05value\x18\x02 \x01(\x0b\x32\x18.seigr.ReplicationStatus:\x02\x38\x01\x1a\x36\n\x14SummaryMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x37\n\x15\x45scalationCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'replication_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _REPLICATIONCONFIG_METADATAENTRY._options = None
  _REPLICATIONCONFIG_METADATAENTRY._serialized_options = b'8\001'
  _REPLICATIONSTATUS_METADATAENTRY._options = None
  _REPLICATIONSTATUS_METADATAENTRY._serialized_options = b'8\001'
  _REPLICATIONEVENTLOG_DETAILSENTRY._options = None
  _REPLICATIONEVENTLOG_DETAILSENTRY._serialized_options = b'8\001'
  _REDUNDANCYMANAGER_SEGMENTPRIORITYENTRY._options = None
  _REDUNDANCYMANAGER_SEGMENTPRIORITYENTRY._serialized_options = b'8\001'
  _REDUNDANCYMANAGER_REDUNDANCYMETADATAENTRY._options = None
  _REDUNDANCYMANAGER_REDUNDANCYMETADATAENTRY._serialized_options = b'8\001'
  _REPLICATIONESCALATION_METADATAENTRY._options = None
  _REPLICATIONESCALATION_METADATAENTRY._serialized_options = b'8\001'
  _REPLICATIONESCALATION_ALERTPREFERENCESENTRY._options = None
  _REPLICATIONESCALATION_ALERTPREFERENCESENTRY._serialized_options = b'8\001'
  _REPLICATIONSUMMARY_SEGMENTSTATUSESENTRY._options = None
  _REPLICATIONSUMMARY_SEGMENTSTATUSESENTRY._serialized_options = b'8\001'
  _REPLICATIONSUMMARY_SUMMARYMETADATAENTRY._options = None
  _REPLICATIONSUMMARY_SUMMARYMETADATAENTRY._serialized_options = b'8\001'
  _REPLICATIONSUMMARY_ESCALATIONCOUNTSENTRY._options = None
  _REPLICATIONSUMMARY_ESCALATIONCOUNTSENTRY._serialized_options = b'8\001'
  _REPLICATIONCONFIG._serialized_start=65
  _REPLICATIONCONFIG._serialized_end=596
  _REPLICATIONCONFIG_METADATAENTRY._serialized_start=549
  _REPLICATIONCONFIG_METADATAENTRY._serialized_end=596
  _REPLICATIONSTATUS._serialized_start=599
  _REPLICATIONSTATUS._serialized_end=1100
  _REPLICATIONSTATUS_METADATAENTRY._serialized_start=549
  _REPLICATIONSTATUS_METADATAENTRY._serialized_end=596
  _REPLICATIONEVENTLOG._serialized_start=1103
  _REPLICATIONEVENTLOG._serialized_end=1469
  _REPLICATIONEVENTLOG_DETAILSENTRY._serialized_start=1423
  _REPLICATIONEVENTLOG_DETAILSENTRY._serialized_end=1469
  _REDUNDANCYMANAGER._serialized_start=1472
  _REDUNDANCYMANAGER._serialized_end=2050
  _REDUNDANCYMANAGER_SEGMENTPRIORITYENTRY._serialized_start=1909
  _REDUNDANCYMANAGER_SEGMENTPRIORITYENTRY._serialized_end=1991
  _REDUNDANCYMANAGER_REDUNDANCYMETADATAENTRY._serialized_start=1993
  _REDUNDANCYMANAGER_REDUNDANCYMETADATAENTRY._serialized_end=2050
  _REPLICATIONESCALATION._serialized_start=2053
  _REPLICATIONESCALATION._serialized_end=2697
  _REPLICATIONESCALATION_METADATAENTRY._serialized_start=549
  _REPLICATIONESCALATION_METADATAENTRY._serialized_end=596
  _REPLICATIONESCALATION_ALERTPREFERENCESENTRY._serialized_start=2642
  _REPLICATIONESCALATION_ALERTPREFERENCESENTRY._serialized_end=2697
  _REPLICATIONSUMMARY._serialized_start=2700
  _REPLICATIONSUMMARY._serialized_end=3473
  _REPLICATIONSUMMARY_SEGMENTSTATUSESENTRY._serialized_start=3280
  _REPLICATIONSUMMARY_SEGMENTSTATUSESENTRY._serialized_end=3360
  _REPLICATIONSUMMARY_SUMMARYMETADATAENTRY._serialized_start=3362
  _REPLICATIONSUMMARY_SUMMARYMETADATAENTRY._serialized_end=3416
  _REPLICATIONSUMMARY_ESCALATIONCOUNTSENTRY._serialized_start=3418
  _REPLICATIONSUMMARY_ESCALATIONCOUNTSENTRY._serialized_end=3473
# @@protoc_insertion_point(module_scope)
