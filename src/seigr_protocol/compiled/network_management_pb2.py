# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: network_management.proto
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
    'network_management.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2
import network_pb2 as network__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x18network_management.proto\x12\x18seigr.network_management\x1a\x0c\x63ommon.proto\x1a\rnetwork.proto\"\xc7\x04\n\nHyphenInfo\x12\x11\n\thyphen_id\x18\x01 \x01(\t\x12\x32\n\x04role\x18\x02 \x01(\x0e\x32$.seigr.network_management.HyphenRole\x12\x38\n\x10primary_protocol\x18\x03 \x01(\x0e\x32\x1e.seigr.network.NetworkProtocol\x12+\n\x06status\x18\x04 \x01(\x0e\x32\x1b.seigr.network.HyphenStatus\x12\x11\n\tlast_seen\x18\x05 \x01(\t\x12\x44\n\x08metadata\x18\x06 \x03(\x0b\x32\x32.seigr.network_management.HyphenInfo.MetadataEntry\x12;\n\x13supported_protocols\x18\x07 \x03(\x0e\x32\x1e.seigr.network.NetworkProtocol\x12\x14\n\x0c\x63urrent_load\x18\x08 \x01(\x03\x12\x14\n\x0clast_updated\x18\t \x01(\t\x12\x1d\n\x15\x61vailable_cpu_percent\x18\n \x01(\x05\x12\x1b\n\x13\x61vailable_memory_mb\x18\x0b \x01(\x05\x12 \n\x18\x61vailable_bandwidth_mbps\x18\x0c \x01(\x05\x12\x1d\n\x15supports_self_healing\x18\r \x01(\x08\x12\x1b\n\x13self_healing_status\x18\x0e \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x93\x04\n\x12\x43onnectivityStatus\x12\x18\n\x10source_hyphen_id\x18\x01 \x01(\t\x12\x18\n\x10target_hyphen_id\x18\x02 \x01(\t\x12\x30\n\x08protocol\x18\x03 \x01(\x0e\x32\x1e.seigr.network.NetworkProtocol\x12\x36\n\x11\x63onnection_status\x18\x04 \x01(\x0e\x32\x1b.seigr.network.HyphenStatus\x12\x1c\n\x14protocol_specific_id\x18\x05 \x01(\t\x12\x12\n\nlatency_ms\x18\x06 \x01(\x05\x12\x11\n\ttimestamp\x18\x07 \x01(\t\x12\x15\n\rerror_message\x18\x08 \x01(\t\x12\x61\n\x13\x63onnection_metadata\x18\t \x03(\x0b\x32\x44.seigr.network_management.ConnectivityStatus.ConnectionMetadataEntry\x12\x18\n\x10packet_loss_rate\x18\n \x01(\x02\x12\x16\n\x0e\x61uto_re_routed\x18\x0b \x01(\x08\x12\x15\n\rre_route_path\x18\x0c \x01(\t\x12\x1c\n\x14\x61lternative_protocol\x18\r \x01(\t\x1a\x39\n\x17\x43onnectionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf2\x03\n\rDataSyncEvent\x12\x0f\n\x07sync_id\x18\x01 \x01(\t\x12\x18\n\x10source_hyphen_id\x18\x02 \x01(\t\x12\x18\n\x10target_hyphen_id\x18\x03 \x01(\t\x12\x30\n\x08protocol\x18\x04 \x01(\x0e\x32\x1e.seigr.network.NetworkProtocol\x12\x11\n\tdata_hash\x18\x05 \x01(\t\x12\x35\n\tsync_type\x18\x06 \x01(\x0e\x32\".seigr.network_management.SyncType\x12\x0f\n\x07success\x18\x07 \x01(\x08\x12\x11\n\ttimestamp\x18\x08 \x01(\t\x12G\n\x08metadata\x18\t \x03(\x0b\x32\x35.seigr.network_management.DataSyncEvent.MetadataEntry\x12\x17\n\x0f\x64\x61ta_size_bytes\x18\n \x01(\x03\x12\x0f\n\x07retries\x18\x0b \x01(\x05\x12\x1f\n\x17\x61\x64\x61ptive_bandwidth_used\x18\x0c \x01(\t\x12\x1a\n\x12redundancy_applied\x18\r \x01(\t\x12\x1b\n\x13network_load_factor\x18\x0e \x01(\x02\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x95\x02\n\x13NetworkAnomalyAlert\x12\x10\n\x08\x61lert_id\x18\x01 \x01(\t\x12\x13\n\x0b\x64\x65tected_by\x18\x02 \x01(\t\x12/\n\x0cthreat_level\x18\x03 \x01(\x0e\x32\x19.seigr.common.ThreatLevel\x12\x13\n\x0b\x64\x65scription\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12M\n\x08metadata\x18\x06 \x03(\x0b\x32;.seigr.network_management.NetworkAnomalyAlert.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\x97\x01\n\nHyphenRole\x12\x12\n\x0eROLE_UNDEFINED\x10\x00\x12\x14\n\x10ROLE_USER_HYPHEN\x10\x01\x12\x18\n\x14ROLE_NON_USER_HYPHEN\x10\x02\x12\x0f\n\x0bROLE_MASTER\x10\x03\x12\x0f\n\x0bROLE_WORKER\x10\x04\x12\x10\n\x0cROLE_GATEWAY\x10\x05\x12\x11\n\rROLE_ADAPTIVE\x10\x06*k\n\x08SyncType\x12\x17\n\x13SYNC_TYPE_UNDEFINED\x10\x00\x12\x12\n\x0eSYNC_TYPE_FULL\x10\x01\x12\x19\n\x15SYNC_TYPE_INCREMENTAL\x10\x02\x12\x17\n\x13SYNC_TYPE_REAL_TIME\x10\x03\x32\x9d\x04\n\x18NetworkManagementService\x12`\n\x13MonitorConnectivity\x12#.seigr.network.NetworkStatusRequest\x1a$.seigr.network.NetworkStatusResponse\x12^\n\x0fPerformDataSync\x12\'.seigr.network_management.DataSyncEvent\x1a\".seigr.network.NetworkOperationLog\x12\x62\n\rReportAnomaly\x12-.seigr.network_management.NetworkAnomalyAlert\x1a\".seigr.network.NetworkOperationLog\x12n\n\x1a\x43heckProtocolCompatibility\x12\'.seigr.network.ProtocolCompatibilityLog\x1a\'.seigr.network.ProtocolCompatibilityLog\x12k\n\x1aRetrieveNetworkPerformance\x12#.seigr.network.NetworkStatusRequest\x1a(.seigr.network.NetworkPerformanceSummaryb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'network_management_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_HYPHENINFO_METADATAENTRY']._loaded_options = None
  _globals['_HYPHENINFO_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_CONNECTIVITYSTATUS_CONNECTIONMETADATAENTRY']._loaded_options = None
  _globals['_CONNECTIVITYSTATUS_CONNECTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_DATASYNCEVENT_METADATAENTRY']._loaded_options = None
  _globals['_DATASYNCEVENT_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_NETWORKANOMALYALERT_METADATAENTRY']._loaded_options = None
  _globals['_NETWORKANOMALYALERT_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_HYPHENROLE']._serialized_start=1985
  _globals['_HYPHENROLE']._serialized_end=2136
  _globals['_SYNCTYPE']._serialized_start=2138
  _globals['_SYNCTYPE']._serialized_end=2245
  _globals['_HYPHENINFO']._serialized_start=84
  _globals['_HYPHENINFO']._serialized_end=667
  _globals['_HYPHENINFO_METADATAENTRY']._serialized_start=620
  _globals['_HYPHENINFO_METADATAENTRY']._serialized_end=667
  _globals['_CONNECTIVITYSTATUS']._serialized_start=670
  _globals['_CONNECTIVITYSTATUS']._serialized_end=1201
  _globals['_CONNECTIVITYSTATUS_CONNECTIONMETADATAENTRY']._serialized_start=1144
  _globals['_CONNECTIVITYSTATUS_CONNECTIONMETADATAENTRY']._serialized_end=1201
  _globals['_DATASYNCEVENT']._serialized_start=1204
  _globals['_DATASYNCEVENT']._serialized_end=1702
  _globals['_DATASYNCEVENT_METADATAENTRY']._serialized_start=620
  _globals['_DATASYNCEVENT_METADATAENTRY']._serialized_end=667
  _globals['_NETWORKANOMALYALERT']._serialized_start=1705
  _globals['_NETWORKANOMALYALERT']._serialized_end=1982
  _globals['_NETWORKANOMALYALERT_METADATAENTRY']._serialized_start=620
  _globals['_NETWORKANOMALYALERT_METADATAENTRY']._serialized_end=667
  _globals['_NETWORKMANAGEMENTSERVICE']._serialized_start=2248
  _globals['_NETWORKMANAGEMENTSERVICE']._serialized_end=2789
# @@protoc_insertion_point(module_scope)
