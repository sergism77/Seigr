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




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13inter_cluster.proto\x12\x12seigr.intercluster\"\xf5\x04\n\x0e\x43lusterRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\t\x12<\n\x0crequest_type\x18\x02 \x01(\x0e\x32&.seigr.intercluster.ClusterRequestType\x12\x19\n\x11origin_cluster_id\x18\x03 \x01(\t\x12\x19\n\x11target_cluster_id\x18\x04 \x01(\t\x12U\n\x12request_parameters\x18\x05 \x03(\x0b\x32\x39.seigr.intercluster.ClusterRequest.RequestParametersEntry\x12\x14\n\x0cinitiated_at\x18\x06 \x01(\t\x12Q\n\x10security_context\x18\x07 \x03(\x0b\x32\x37.seigr.intercluster.ClusterRequest.SecurityContextEntry\x12\x1e\n\x16require_acknowledgment\x18\x08 \x01(\x08\x12Q\n\x10request_metadata\x18\t \x03(\x0b\x32\x37.seigr.intercluster.ClusterRequest.RequestMetadataEntry\x1a\x38\n\x16RequestParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14SecurityContextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14RequestMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xe6\x03\n\x0f\x43lusterResponse\x12\x13\n\x0bresponse_id\x18\x01 \x01(\t\x12\x12\n\nrequest_id\x18\x02 \x01(\t\x12>\n\rresponse_type\x18\x03 \x01(\x0e\x32\'.seigr.intercluster.ClusterResponseType\x12\x19\n\x11origin_cluster_id\x18\x04 \x01(\t\x12\x19\n\x11target_cluster_id\x18\x05 \x01(\t\x12\x1a\n\x12response_timestamp\x18\x06 \x01(\t\x12T\n\x11response_metadata\x18\x07 \x03(\x0b\x32\x39.seigr.intercluster.ClusterResponse.ResponseMetadataEntry\x12\x16\n\x0estatus_message\x18\x08 \x01(\t\x12\x41\n\x07payload\x18\t \x03(\x0b\x32\x30.seigr.intercluster.ClusterResponse.PayloadEntry\x1a\x37\n\x15ResponseMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a.\n\x0cPayloadEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\"\xb2\x03\n\x0c\x44\x61taTransfer\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\x12\x19\n\x11source_cluster_id\x18\x02 \x01(\t\x12\x1e\n\x16\x64\x65stination_cluster_id\x18\x03 \x01(\t\x12\x14\n\x0c\x64\x61ta_payload\x18\x04 \x01(\x0c\x12\x11\n\tdata_type\x18\x05 \x01(\t\x12\x19\n\x11\x65ncryption_scheme\x18\x06 \x01(\t\x12\x1a\n\x12\x63ompression_method\x18\x07 \x01(\t\x12\x17\n\x0ftransfer_format\x18\x08 \x01(\t\x12\x17\n\x0f\x64\x61ta_size_bytes\x18\t \x01(\x03\x12\x1a\n\x12validate_integrity\x18\n \x01(\x08\x12\x18\n\x10transfer_timeout\x18\x0b \x01(\x05\x12Q\n\x11transfer_metadata\x18\x0c \x03(\x0b\x32\x36.seigr.intercluster.DataTransfer.TransferMetadataEntry\x1a\x37\n\x15TransferMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf2\x02\n\x18\x43lusterEventSubscription\x12\x17\n\x0fsubscription_id\x18\x01 \x01(\t\x12\x1d\n\x15subscriber_cluster_id\x18\x02 \x01(\t\x12\x41\n\x11subscribed_events\x18\x03 \x03(\x0e\x32&.seigr.intercluster.ClusterRequestType\x12#\n\x1breceive_async_notifications\x18\x04 \x01(\x08\x12\x65\n\x15subscription_metadata\x18\x05 \x03(\x0b\x32\x46.seigr.intercluster.ClusterEventSubscription.SubscriptionMetadataEntry\x12\x12\n\ncreated_at\x18\x06 \x01(\t\x1a;\n\x19SubscriptionMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb3\x02\n\x0eTransferStatus\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\x12\x16\n\x0e\x63urrent_status\x18\x02 \x01(\t\x12\x14\n\x0clast_updated\x18\x03 \x01(\t\x12\x1b\n\x13progress_percentage\x18\x04 \x01(\x01\x12\x19\n\x11source_cluster_id\x18\x05 \x01(\t\x12\x1e\n\x16\x64\x65stination_cluster_id\x18\x06 \x01(\t\x12O\n\x0fstatus_metadata\x18\x07 \x03(\x0b\x32\x36.seigr.intercluster.TransferStatus.StatusMetadataEntry\x1a\x35\n\x13StatusMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb3\x02\n\x1c\x43lusterCommunicationErrorLog\x12\x10\n\x08\x65rror_id\x18\x01 \x01(\t\x12\x1b\n\x13\x61\x66\x66\x65\x63ted_cluster_id\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x15\n\rerror_message\x18\x04 \x01(\t\x12\x12\n\nrequest_id\x18\x05 \x01(\t\x12\x13\n\x0bresponse_id\x18\x06 \x01(\t\x12[\n\x0e\x65rror_metadata\x18\x07 \x03(\x0b\x32\x43.seigr.intercluster.ClusterCommunicationErrorLog.ErrorMetadataEntry\x1a\x34\n\x12\x45rrorMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"K\n\x12\x43lusterResponseAck\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\x12\x13\n\x0bresponse_id\x18\x03 \x01(\t\",\n\x15TransferStatusRequest\x12\x13\n\x0btransfer_id\x18\x01 \x01(\t\"`\n\x19\x43ommunicationErrorRequest\x12\x43\n\terror_log\x18\x01 \x01(\x0b\x32\x30.seigr.intercluster.ClusterCommunicationErrorLog\">\n\x1a\x43ommunicationErrorResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t\"]\n ClusterEventSubscriptionResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x17\n\x0fsubscription_id\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t*\x9e\x01\n\x12\x43lusterRequestType\x12\x1a\n\x16REQUEST_TYPE_UNDEFINED\x10\x00\x12\x14\n\x10REQUEST_RESOURCE\x10\x01\x12\x10\n\x0cREQUEST_DATA\x10\x02\x12\x1c\n\x18REQUEST_WORKLOAD_BALANCE\x10\x03\x12\x12\n\x0eREQUEST_STATUS\x10\x04\x12\x12\n\x0eREQUEST_CUSTOM\x10\x05*\xc3\x01\n\x13\x43lusterResponseType\x12\x1b\n\x17RESPONSE_TYPE_UNDEFINED\x10\x00\x12\x19\n\x15RESPONSE_ACKNOWLEDGED\x10\x01\x12\x1b\n\x17RESPONSE_DATA_DELIVERED\x10\x02\x12\x15\n\x11RESPONSE_ACCEPTED\x10\x03\x12\x15\n\x11RESPONSE_DECLINED\x10\x04\x12\x14\n\x10RESPONSE_PENDING\x10\x05\x12\x13\n\x0fRESPONSE_FAILED\x10\x06\x32\xaa\x05\n InterClusterCommunicationService\x12]\n\x12SendClusterRequest\x12\".seigr.intercluster.ClusterRequest\x1a#.seigr.intercluster.ClusterResponse\x12i\n\x1a\x41\x63knowledgeClusterResponse\x12#.seigr.intercluster.ClusterResponse\x1a&.seigr.intercluster.ClusterResponseAck\x12\\\n\x14InitiateDataTransfer\x12 .seigr.intercluster.DataTransfer\x1a\".seigr.intercluster.TransferStatus\x12\x66\n\x15MonitorTransferStatus\x12).seigr.intercluster.TransferStatusRequest\x1a\".seigr.intercluster.TransferStatus\x12v\n\x15LogCommunicationError\x12-.seigr.intercluster.CommunicationErrorRequest\x1a..seigr.intercluster.CommunicationErrorResponse\x12~\n\x18SubscribeToClusterEvents\x12,.seigr.intercluster.ClusterEventSubscription\x1a\x34.seigr.intercluster.ClusterEventSubscriptionResponseb\x06proto3')

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
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._loaded_options = None
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._loaded_options = None
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_CLUSTERREQUESTTYPE']._serialized_start=2975
  _globals['_CLUSTERREQUESTTYPE']._serialized_end=3133
  _globals['_CLUSTERRESPONSETYPE']._serialized_start=3136
  _globals['_CLUSTERRESPONSETYPE']._serialized_end=3331
  _globals['_CLUSTERREQUEST']._serialized_start=44
  _globals['_CLUSTERREQUEST']._serialized_end=673
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._serialized_start=505
  _globals['_CLUSTERREQUEST_REQUESTPARAMETERSENTRY']._serialized_end=561
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._serialized_start=563
  _globals['_CLUSTERREQUEST_SECURITYCONTEXTENTRY']._serialized_end=617
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._serialized_start=619
  _globals['_CLUSTERREQUEST_REQUESTMETADATAENTRY']._serialized_end=673
  _globals['_CLUSTERRESPONSE']._serialized_start=676
  _globals['_CLUSTERRESPONSE']._serialized_end=1162
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._serialized_start=1059
  _globals['_CLUSTERRESPONSE_RESPONSEMETADATAENTRY']._serialized_end=1114
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._serialized_start=1116
  _globals['_CLUSTERRESPONSE_PAYLOADENTRY']._serialized_end=1162
  _globals['_DATATRANSFER']._serialized_start=1165
  _globals['_DATATRANSFER']._serialized_end=1599
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._serialized_start=1544
  _globals['_DATATRANSFER_TRANSFERMETADATAENTRY']._serialized_end=1599
  _globals['_CLUSTEREVENTSUBSCRIPTION']._serialized_start=1602
  _globals['_CLUSTEREVENTSUBSCRIPTION']._serialized_end=1972
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_start=1913
  _globals['_CLUSTEREVENTSUBSCRIPTION_SUBSCRIPTIONMETADATAENTRY']._serialized_end=1972
  _globals['_TRANSFERSTATUS']._serialized_start=1975
  _globals['_TRANSFERSTATUS']._serialized_end=2282
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_start=2229
  _globals['_TRANSFERSTATUS_STATUSMETADATAENTRY']._serialized_end=2282
  _globals['_CLUSTERCOMMUNICATIONERRORLOG']._serialized_start=2285
  _globals['_CLUSTERCOMMUNICATIONERRORLOG']._serialized_end=2592
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_start=2540
  _globals['_CLUSTERCOMMUNICATIONERRORLOG_ERRORMETADATAENTRY']._serialized_end=2592
  _globals['_CLUSTERRESPONSEACK']._serialized_start=2594
  _globals['_CLUSTERRESPONSEACK']._serialized_end=2669
  _globals['_TRANSFERSTATUSREQUEST']._serialized_start=2671
  _globals['_TRANSFERSTATUSREQUEST']._serialized_end=2715
  _globals['_COMMUNICATIONERRORREQUEST']._serialized_start=2717
  _globals['_COMMUNICATIONERRORREQUEST']._serialized_end=2813
  _globals['_COMMUNICATIONERRORRESPONSE']._serialized_start=2815
  _globals['_COMMUNICATIONERRORRESPONSE']._serialized_end=2877
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE']._serialized_start=2879
  _globals['_CLUSTEREVENTSUBSCRIPTIONRESPONSE']._serialized_end=2972
  _globals['_INTERCLUSTERCOMMUNICATIONSERVICE']._serialized_start=3334
  _globals['_INTERCLUSTERCOMMUNICATIONSERVICE']._serialized_end=4016
# @@protoc_insertion_point(module_scope)
