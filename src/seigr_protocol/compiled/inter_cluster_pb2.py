# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: inter_cluster.proto
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
    'inter_cluster.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2
import error_handling_pb2 as error__handling__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13inter_cluster.proto\x12\x12seigr.intercluster\x1a\x0c\x63ommon.proto\x1a\x14\x65rror_handling.proto\"\xbf\x05\n\x0e\x43lusterRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12<\n\x0crequest_type\x18\x02 \x01(\x0e\x32&.seigr.intercluster.ClusterRequestType\x12\x19\n\x11origin_cluster_id\x18\x03 \x01(\t\x12\x19\n\x11target_cluster_id\x18\x04 \x01(\t\x12U\n\x12request_parameters\x18\x05 \x03(\x0b\x32\x39.seigr.intercluster.ClusterRequest.RequestParametersEntry\x12-\n\x0cinitiated_at\x18\x06 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12Q\n\x10security_context\x18\x07 \x03(\x0b\x32\x37.seigr.intercluster.ClusterRequest.SecurityContextEntry\x12\x1e\n\x16require_acknowledgment\x18\x08 \x01(\x08\x12/\n\x0cthreat_level\x18\t \x01(\x0e\x32\x19.seigr.common.ThreatLevel\x12Q\n\x10request_metadata\x18\n \x03(\x0b\x32\x37.seigr.intercluster.ClusterRequest.RequestMetadataEntry\x1a\x38\n\x16RequestParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14SecurityContextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14RequestMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc3\x04\n\x0f\x43lusterResponse\x12\x13\n\x0bresponse_id\x18\x01 \x01(\t\x12\x12\n\nrequest_id\x18\x02 \x01(\t\x12>\n\rresponse_type\x18\x03 \x01(\x0e\x32\'.seigr.intercluster.ClusterResponseType\x12\x19\n\x11origin_cluster_id\x18\x04 \x01(\t\x12\x19\n\x11target_cluster_id\x18\x05 \x01(\t\x12\x33\n\x12response_timestamp\x18\x06 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12T\n\x11response_metadata\x18\x07 \x03(\x0b\x32\x39.seigr.intercluster.ClusterResponse.ResponseMetadataEntry\x12\x16\n\x0estatus_message\x18\x08 \x01(\t\x12\x41\n\x07payload\x18\t \x03(\x0b\x32\x30.seigr.intercluster.ClusterResponse.PayloadEntry\x12\x42\n\x0fimpact_analysis\x18\n \x01(\x0b\x32).seigr.error_handling.ErrorImpactAnalysis\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a.\n\x0cPayloadEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\"\xe1\x03\n\x0c\x44\x61taTransfer\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\x12\x19\n\x11source_cluster_id\x18\x02 \x01(\t\x12\x1e\n\x16\x64\x65stination_cluster_id\x18\x03 \x01(\t\x12\x14\n\x0c\x64\x61ta_payload\x18\x04 \x01(\x0c\x12\x11\n\tdata_type\x18\x05 \x01(\t\x12\x19\n\x11\x65ncryption_scheme\x18\x06 \x01(\t\x12\x1a\n\x12\x63ompression_method\x18\x07 \x01(\t\x12\x17\n\x0ftransfer_format\x18\x08 \x01(\t\x12\x17\n\x0f\x64\x61ta_size_bytes\x18\t \x01(\x03\x12\x1a\n\x12validate_integrity\x18\n \x01(\x08\x12\x18\n\x10transfer_timeout\x18\x0b \x01(\x05\x12Q\n\x11transfer_metadata\x18\x0c \x03(\x0b\x32\x36.seigr.intercluster.DataTransfer.TransferMetadataEntry\x12-\n\x08priority\x18\r \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x1a\x37\n\x15TransferMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe4\x02\n\x0eTransferStatus\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\x12\x16\n\x0e\x63urrent_status\x18\x02 \x01(\t\x12-\n\x0clast_updated\x18\x03 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x1b\n\x13progress_percentage\x18\x04 \x01(\x01\x12\x19\n\x11source_cluster_id\x18\x05 \x01(\t\x12\x1e\n\x16\x64\x65stination_cluster_id\x18\x06 \x01(\t\x12O\n\x0fstatus_metadata\x18\x07 \x03(\x0b\x32\x36.seigr.intercluster.TransferStatus.StatusMetadataEntry\x12\x16\n\x0e\x66\x61ilure_reason\x18\x08 \x01(\t\x1a\x35\n\x13StatusMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x98\x03\n\x1c\x43lusterCommunicationErrorLog\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12\x1b\n\x13\x61\x66\x66\x65\x63ted_cluster_id\x18\x02 \x01(\t\x12*\n\ttimestamp\x18\x03 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x15\n\rerror_message\x18\x04 \x01(\t\x12\x12\n\nrequest_id\x18\x05 \x01(\t\x12\x13\n\x0bresponse_id\x18\x06 \x01(\t\x12J\n\x13resolution_strategy\x18\x07 \x01(\x0e\x32-.seigr.error_handling.ErrorResolutionStrategy\x12[\n\x0e\x65rror_metadata\x18\x08 \x03(\x0b\x32\x43.seigr.intercluster.ClusterCommunicationErrorLog.ErrorMetadataEntry\x1a\x34\n\x12\x45rrorMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xba\x02\n\x12\x43lusterResponseAck\x12\x0e\n\x06\x61\x63k_id\x18\x01 \x01(\t\x12\x13\n\x0bresponse_id\x18\x02 \x01(\t\x12\x19\n\x11origin_cluster_id\x18\x03 \x01(\t\x12\x19\n\x11target_cluster_id\x18\x04 \x01(\t\x12.\n\rack_timestamp\x18\x05 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12M\n\x0c\x61\x63k_metadata\x18\x06 \x03(\x0b\x32\x37.seigr.intercluster.ClusterResponseAck.AckMetadataEntry\x12\x16\n\x0estatus_message\x18\x07 \x01(\t\x1a\x32\n\x10\x41\x63kMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xdd\x01\n\x15TransferStatusRequest\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\x12\x1d\n\x15requesting_cluster_id\x18\x02 \x01(\t\x12X\n\x10request_metadata\x18\x03 \x03(\x0b\x32>.seigr.intercluster.TransferStatusRequest.RequestMetadataEntry\x1a\x36\n\x14RequestMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xd7\x02\n\x19\x43ommunicationErrorRequest\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12\x1b\n\x13\x61\x66\x66\x65\x63ted_cluster_id\x18\x02 \x01(\t\x12\x19\n\x11origin_cluster_id\x18\x03 \x01(\t\x12*\n\ttimestamp\x18\x04 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x15\n\rerror_message\x18\x05 \x01(\t\x12\x1d\n\x15resolution_suggestion\x18\x06 \x01(\t\x12X\n\x0e\x65rror_metadata\x18\x07 \x03(\x0b\x32@.seigr.intercluster.CommunicationErrorRequest.ErrorMetadataEntry\x1a\x34\n\x12\x45rrorMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xea\x01\n\x1a\x43ommunicationErrorResponse\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12\x0f\n\x07success\x18\x02 \x01(\x08\x12\x0f\n\x07message\x18\x03 \x01(\t\x12_\n\x11response_metadata\x18\x04 \x03(\x0b\x32\x44.seigr.intercluster.CommunicationErrorResponse.ResponseMetadataEntry\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe8\x02\n\x18\x43lusterEventSubscription\x12\x17\n\x0fsubscription_id\x18\x01 \x01(\t\x12\x12\n\ncluster_id\x18\x02 \x01(\t\x12\x13\n\x0b\x65vent_types\x18\x03 \x03(\t\x12\x33\n\x12subscription_start\x18\x04 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x31\n\x10subscription_end\x18\x05 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x65\n\x15subscription_metadata\x18\x06 \x03(\x0b\x32\x46.seigr.intercluster.ClusterEventSubscription.SubscriptionMetadataEntry\x1a;\n\x19SubscriptionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xfd\x01\n ClusterEventSubscriptionResponse\x12\x17\n\x0fsubscription_id\x18\x01 \x01(\t\x12\x0f\n\x07success\x18\x02 \x01(\x08\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x65\n\x11response_metadata\x18\x04 \x03(\x0b\x32J.seigr.intercluster.ClusterEventSubscriptionResponse.ResponseMetadataEntry\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xda\x01\n\x12\x43lusterRequestType\x12\x1a\n\x16REQUEST_TYPE_UNDEFINED\x10\x00\x12\x14\n\x10REQUEST_RESOURCE\x10\x01\x12\x10\n\x0cREQUEST_DATA\x10\x02\x12\x1c\n\x18REQUEST_WORKLOAD_BALANCE\x10\x03\x12\x12\n\x0eREQUEST_STATUS\x10\x04\x12\x12\n\x0eREQUEST_CUSTOM\x10\x05\x12\x1c\n\x18REQUEST_COMPLIANCE_CHECK\x10\x06\x12\x1c\n\x18REQUEST_REPLICATION_TASK\x10\x07*\xe6\x01\n\x13\x43lusterResponseType\x12\x1b\n\x17RESPONSE_TYPE_UNDEFINED\x10\x00\x12\x19\n\x15RESPONSE_ACKNOWLEDGED\x10\x01\x12\x1b\n\x17RESPONSE_DATA_DELIVERED\x10\x02\x12\x15\n\x11RESPONSE_ACCEPTED\x10\x03\x12\x15\n\x11RESPONSE_DECLINED\x10\x04\x12\x14\n\x10RESPONSE_PENDING\x10\x05\x12\x13\n\x0fRESPONSE_FAILED\x10\x06\x12!\n\x1dRESPONSE_COMPLIANCE_VALIDATED\x10\x07\x32\xa9\x05\n InterClusterCommunicationService\x12]\n\x12SendClusterRequest\x12\".seigr.intercluster.ClusterRequest\x1a#.seigr.intercluster.ClusterResponse\x12i\n\x1a\x41\x63knowledgeClusterResponse\x12#.seigr.intercluster.ClusterResponse\x1a&.seigr.intercluster.ClusterResponseAck\x12\\\n\x14InitiateDataTransfer\x12 .seigr.intercluster.DataTransfer\x1a\".seigr.intercluster.TransferStatus\x12\x66\n\x15MonitorTransferStatus\x12).seigr.intercluster.TransferStatusRequest\x1a\".seigr.intercluster.TransferStatus\x12v\n\x15LogCommunicationError\x12-.seigr.intercluster.CommunicationErrorRequest\x1a..seigr.intercluster.CommunicationErrorResponse\x12}\n\x17ManageEventSubscription\x12,.seigr.intercluster.ClusterEventSubscription\x1a\x34.seigr.intercluster.ClusterEventSubscriptionResponseb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'inter_cluster_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._loaded_options = None
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._loaded_options = None
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._loaded_options = None
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._serialized_options = b'8\001'
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._loaded_options = None
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._loaded_options = None
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERRESPONSEACK_ACKMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTERRESPONSEACK_ACKMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_TRANSFERSTATUSREQUEST_REQUESTMETADATAENTRY']._loaded_options = None
  _globals['_TRANSFERSTATUSREQUEST_REQUESTMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_COMMUNICATIONERRORREQUEST_ERRORMETADATAENTRY']._loaded_options = None
  _globals['_COMMUNICATIONERRORREQUEST_ERRORMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_COMMUNICATIONERRORRESPONSE_RESPONSEMETADATAENTRY']._loaded_options = None
  _globals['_COMMUNICATIONERRORRESPONSE_RESPONSEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE_RESPONSEMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE_RESPONSEMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERREQUESTTYPE']._serialized_start=4365
  _globals['_CLUSTERREQUESTTYPE']._serialized_end=4583
  _globals['_CLUSTERRESPONSETYPE']._serialized_start=4586
  _globals['_CLUSTERRESPONSETYPE']._serialized_end=4816
  _globals['_CLUSTERREQUEST']._serialized_start=80
  _globals['_CLUSTERREQUEST']._serialized_end=783
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._serialized_start=615
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._serialized_end=671
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._serialized_start=673
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._serialized_end=727
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._serialized_start=729
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._serialized_end=783
  _globals['_CLUSTERRESPONSE']._serialized_start=786
  _globals['_CLUSTERRESPONSE']._serialized_end=1365
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._serialized_start=1262
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._serialized_end=1317
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._serialized_start=1319
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._serialized_end=1365
  _globals['_DATATRANSFER']._serialized_start=1368
  _globals['_DATATRANSFER']._serialized_end=1849
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._serialized_start=1794
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._serialized_end=1849
  _globals['_TRANSFERSTATUS']._serialized_start=1852
  _globals['_TRANSFERSTATUS']._serialized_end=2208
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_start=2155
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_end=2208
  _globals['_CLUSTERCOMMUNICATIONERRORLOG']._serialized_start=2211
  _globals['_CLUSTERCOMMUNICATIONERRORLOG']._serialized_end=2619
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_start=2567
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_end=2619
  _globals['_CLUSTERRESPONSEACK']._serialized_start=2622
  _globals['_CLUSTERRESPONSEACK']._serialized_end=2936
  _globals['_CLUSTERRESPONSEACK_ACKMETADATAENTRY']._serialized_start=2886
  _globals['_CLUSTERRESPONSEACK_ACKMETADATAENTRY']._serialized_end=2936
  _globals['_TRANSFERSTATUSREQUEST']._serialized_start=2939
  _globals['_TRANSFERSTATUSREQUEST']._serialized_end=3160
  _globals['_TRANSFERSTATUSREQUEST_REQUESTMETADATAENTRY']._serialized_start=729
  _globals['_TRANSFERSTATUSREQUEST_REQUESTMETADATAENTRY']._serialized_end=783
  _globals['_COMMUNICATIONERRORREQUEST']._serialized_start=3163
  _globals['_COMMUNICATIONERRORREQUEST']._serialized_end=3506
  _globals['_COMMUNICATIONERRORREQUEST_ERRORMETADATAENTRY']._serialized_start=2567
  _globals['_COMMUNICATIONERRORREQUEST_ERRORMETADATAENTRY']._serialized_end=2619
  _globals['_COMMUNICATIONERRORRESPONSE']._serialized_start=3509
  _globals['_COMMUNICATIONERRORRESPONSE']._serialized_end=3743
  _globals['_COMMUNICATIONERRORRESPONSE_RESPONSEMETADATAENTRY']._serialized_start=1262
  _globals['_COMMUNICATIONERRORRESPONSE_RESPONSEMETADATAENTRY']._serialized_end=1317
  _globals['_CLUSTEREVENTSUBSCRIPTION']._serialized_start=3746
  _globals['_CLUSTEREVENTSUBSCRIPTION']._serialized_end=4106
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_start=4047
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_end=4106
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE']._serialized_start=4109
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE']._serialized_end=4362
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE_RESPONSEMETADATAENTRY']._serialized_start=1262
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE_RESPONSEMETADATAENTRY']._serialized_end=1317
  _globals['_INTERCLUSTERCOMMUNICATIONSERVICE']._serialized_start=4819
  _globals['_INTERCLUSTERCOMMUNICATIONSERVICE']._serialized_end=5500
# @@protoc_insertion_point(module_scope)
