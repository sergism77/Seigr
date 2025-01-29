# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: notification.proto
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
    'notification.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x12notification.proto\x12\x12seigr.notification\x1a\x1bgoogle/protobuf/empty.proto\x1a\x0c\x63ommon.proto\"\xd1\x06\n\x0cNotification\x12\x17\n\x0fnotification_id\x18\x01 \x01(\t\x12\x32\n\x04type\x18\x02 \x01(\x0e\x32$.seigr.notification.NotificationType\x12\x0f\n\x07message\x18\x03 \x01(\t\x12\x14\n\x0crecipient_id\x18\x04 \x01(\t\x12;\n\x0f\x64\x65livery_method\x18\x05 \x01(\x0e\x32\".seigr.notification.DeliveryMethod\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12@\n\x08metadata\x18\x07 \x03(\x0b\x32..seigr.notification.Notification.MetadataEntry\x12\x1f\n\x17requires_acknowledgment\x18\x08 \x01(\x08\x12\x13\n\x0bretry_count\x18\t \x01(\x05\x12-\n\x08priority\x18\n \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x12\x12\n\naction_url\x18\x0b \x01(\t\x12\x1c\n\x14time_to_live_seconds\x18\x0c \x01(\x05\x12\x18\n\x10\x61\x63tionable_items\x18\r \x03(\t\x12\x15\n\raggregateable\x18\x0e \x01(\x08\x12O\n\x10response_options\x18\x0f \x03(\x0b\x32\x35.seigr.notification.Notification.ResponseOptionsEntry\x12\x14\n\x0c\x63\x61llback_url\x18\x10 \x01(\t\x12U\n\x13\x61\x64\x61ptive_parameters\x18\x11 \x03(\x0b\x32\x38.seigr.notification.Notification.AdaptiveParametersEntry\x12\x11\n\ttenant_id\x18\x12 \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14ResponseOptionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x39\n\x17\x41\x64\x61ptiveParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb8\x03\n\x12NotificationStatus\x12\x17\n\x0fnotification_id\x18\x01 \x01(\t\x12\x14\n\x0crecipient_id\x18\x02 \x01(\t\x12\x11\n\tdelivered\x18\x03 \x01(\x08\x12\x14\n\x0c\x61\x63knowledged\x18\x04 \x01(\x08\x12\x14\n\x0c\x64\x65livered_at\x18\x05 \x01(\t\x12\x17\n\x0f\x61\x63knowledged_at\x18\x06 \x01(\t\x12\x16\n\x0e\x66\x61ilure_reason\x18\x07 \x01(\t\x12W\n\x11\x64\x65livery_metadata\x18\x08 \x03(\x0b\x32<.seigr.notification.NotificationStatus.DeliveryMetadataEntry\x12\x16\n\x0eretry_attempts\x18\t \x01(\x05\x12\x1c\n\x14last_retry_timestamp\x18\n \x01(\t\x12\x19\n\x11\x65scalation_policy\x18\x0b \x01(\t\x12 \n\x18\x61\x64\x61ptive_response_action\x18\x0c \x01(\t\x1a\x37\n\x15\x44\x65liveryMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x80\x06\n\x13NotificationHistory\x12\x14\n\x0crecipient_id\x18\x01 \x01(\t\x12\x37\n\rnotifications\x18\x02 \x03(\x0b\x32 .seigr.notification.Notification\x12\x12\n\nstart_date\x18\x03 \x01(\t\x12\x10\n\x08\x65nd_date\x18\x04 \x01(\t\x12\\\n\x13notification_counts\x18\x05 \x03(\x0b\x32?.seigr.notification.NotificationHistory.NotificationCountsEntry\x12\x1b\n\x13total_notifications\x18\x06 \x01(\x05\x12T\n\x0fpriority_counts\x18\x07 \x03(\x0b\x32;.seigr.notification.NotificationHistory.PriorityCountsEntry\x12_\n\x15response_time_average\x18\x08 \x03(\x0b\x32@.seigr.notification.NotificationHistory.ResponseTimeAverageEntry\x12Z\n\x12\x65ngagement_metrics\x18\t \x03(\x0b\x32>.seigr.notification.NotificationHistory.EngagementMetricsEntry\x1a\x39\n\x17NotificationCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x35\n\x13PriorityCountsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a:\n\x18ResponseTimeAverageEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x02:\x02\x38\x01\x1a\x38\n\x16\x45ngagementMetricsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc5\x06\n\x17NotificationPreferences\x12\x14\n\x0crecipient_id\x18\x01 \x01(\t\x12=\n\x11preferred_methods\x18\x02 \x03(\x0e\x32\".seigr.notification.DeliveryMethod\x12\x1a\n\x12mute_notifications\x18\x03 \x01(\x08\x12Z\n\x10type_preferences\x18\x04 \x03(\x0b\x32@.seigr.notification.NotificationPreferences.TypePreferencesEntry\x12\x1f\n\x17max_daily_notifications\x18\x05 \x01(\x05\x12\x1c\n\x14\x64o_not_disturb_start\x18\x06 \x01(\t\x12\x1a\n\x12\x64o_not_disturb_end\x18\x07 \x01(\t\x12\x35\n\x10minimum_priority\x18\x08 \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x12$\n\x1c\x63ustom_notification_interval\x18\t \x01(\t\x12\x64\n\x15\x65scalation_conditions\x18\n \x03(\x0b\x32\x45.seigr.notification.NotificationPreferences.EscalationConditionsEntry\x12\x1a\n\x12\x64ynamic_thresholds\x18\x0b \x01(\x08\x12 \n\x18max_urgent_notifications\x18\x0c \x01(\x05\x12V\n\x0e\x63ustom_filters\x18\r \x03(\x0b\x32>.seigr.notification.NotificationPreferences.CustomFiltersEntry\x1a\x36\n\x14TypePreferencesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a;\n\x19\x45scalationConditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x34\n\x12\x43ustomFiltersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xa3\x03\n\x11NotificationBatch\x12\x10\n\x08\x62\x61tch_id\x18\x01 \x01(\t\x12\x37\n\rnotifications\x18\x02 \x03(\x0b\x32 .seigr.notification.Notification\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12;\n\x0f\x64\x65livery_method\x18\x04 \x01(\x0e\x32\".seigr.notification.DeliveryMethod\x12\x45\n\x08metadata\x18\x05 \x03(\x0b\x32\x33.seigr.notification.NotificationBatch.MetadataEntry\x12%\n\x1drequires_batch_acknowledgment\x18\x06 \x01(\x08\x12\x15\n\rtotal_retries\x18\x07 \x01(\x05\x12\x1e\n\x16\x61\x64\x61ptive_batch_scaling\x18\x08 \x01(\x08\x12\x1d\n\x15\x62\x61tch_priority_factor\x18\t \x01(\x02\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xb0\x04\n\x14NotificationSchedule\x12\x17\n\x0fnotification_id\x18\x01 \x01(\t\x12\x16\n\x0escheduled_time\x18\x02 \x01(\t\x12\x11\n\trecurring\x18\x03 \x01(\x08\x12\x1a\n\x12recurrence_pattern\x18\x04 \x01(\t\x12\x10\n\x08\x65nd_date\x18\x05 \x01(\t\x12]\n\x13scheduling_metadata\x18\x06 \x03(\x0b\x32@.seigr.notification.NotificationSchedule.SchedulingMetadataEntry\x12\x1c\n\x14grace_period_minutes\x18\x07 \x01(\x05\x12\x1d\n\x15\x61uto_retry_on_failure\x18\x08 \x01(\x08\x12\x1d\n\x15\x61\x64\x61ptive_grace_period\x18\t \x01(\x05\x12\x1f\n\x17user_activity_dependent\x18\n \x01(\x08\x12W\n\x10\x66\x61llback_options\x18\x0b \x03(\x0b\x32=.seigr.notification.NotificationSchedule.FallbackOptionsEntry\x1a\x39\n\x17SchedulingMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14\x46\x61llbackOptionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xa8\x02\n\x0bSystemAlert\x12\x10\n\x08\x61lert_id\x18\x01 \x01(\t\x12\x12\n\nalert_type\x18\x02 \x01(\t\x12-\n\x08priority\x18\x03 \x01(\x0e\x32\x1b.seigr.common.PriorityLevel\x12\x0f\n\x07message\x18\x04 \x01(\t\x12\x14\n\x0ctriggered_at\x18\x05 \x01(\t\x12J\n\x0e\x61lert_metadata\x18\x06 \x03(\x0b\x32\x32.seigr.notification.SystemAlert.AlertMetadataEntry\x12\x1b\n\x13\x65scalation_pathways\x18\x07 \x03(\t\x1a\x34\n\x12\x41lertMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xc9\x01\n\x10NotificationType\x12\x1a\n\x16NOTIFICATION_UNDEFINED\x10\x00\x12\x15\n\x11NOTIFICATION_INFO\x10\x01\x12\x16\n\x12NOTIFICATION_ALERT\x10\x02\x12\x18\n\x14NOTIFICATION_WARNING\x10\x03\x12\x16\n\x12NOTIFICATION_ERROR\x10\x04\x12\x18\n\x14NOTIFICATION_SUCCESS\x10\x05\x12\x1e\n\x1aNOTIFICATION_SYSTEM_UPDATE\x10\x06*\xbd\x01\n\x0e\x44\x65liveryMethod\x12\x16\n\x12\x44\x45LIVERY_UNDEFINED\x10\x00\x12\x12\n\x0e\x44\x45LIVERY_EMAIL\x10\x01\x12\x10\n\x0c\x44\x45LIVERY_SMS\x10\x02\x12\x11\n\rDELIVERY_PUSH\x10\x03\x12\x19\n\x15\x44\x45LIVERY_SYSTEM_ALERT\x10\x04\x12\x14\n\x10\x44\x45LIVERY_WEBHOOK\x10\x05\x12\x12\n\x0e\x44\x45LIVERY_BATCH\x10\x06\x12\x15\n\x11\x44\x45LIVERY_ADAPTIVE\x10\x07\x32\xee\x03\n\x13NotificationService\x12\\\n\x10SendNotification\x12 .seigr.notification.Notification\x1a&.seigr.notification.NotificationStatus\x12Y\n\x08\x42ulkSend\x12%.seigr.notification.NotificationBatch\x1a&.seigr.notification.NotificationStatus\x12m\n\x11UpdatePreferences\x12+.seigr.notification.NotificationPreferences\x1a+.seigr.notification.NotificationPreferences\x12\x63\n\x0fRetrieveHistory\x12\'.seigr.notification.NotificationHistory\x1a\'.seigr.notification.NotificationHistory\x12J\n\x0fGetSystemAlerts\x12\x16.google.protobuf.Empty\x1a\x1f.seigr.notification.SystemAlertb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'notification_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  DESCRIPTOR._loaded_options = None
  _globals['_NOTIFICATION_METADATAENTRY']._loaded_options = None
  _globals['_NOTIFICATION_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATION_RESPONSEOPTIONSENTRY']._loaded_options = None
  _globals['_NOTIFICATION_RESPONSEOPTIONSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATION_ADAPTIVEPARAMETERSENTRY']._loaded_options = None
  _globals['_NOTIFICATION_ADAPTIVEPARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONSTATUS_DELIVERYMETADATAENTRY']._loaded_options = None
  _globals['_NOTIFICATIONSTATUS_DELIVERYMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONHISTORY_NOTIFICATIONCOUNTSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONHISTORY_NOTIFICATIONCOUNTSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONHISTORY_PRIORITYCOUNTSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONHISTORY_PRIORITYCOUNTSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONHISTORY_RESPONSETIMEAVERAGEENTRY']._loaded_options = None
  _globals['_NOTIFICATIONHISTORY_RESPONSETIMEAVERAGEENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONHISTORY_ENGAGEMENTMETRICSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONHISTORY_ENGAGEMENTMETRICSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONPREFERENCES_TYPEPREFERENCESENTRY']._loaded_options = None
  _globals['_NOTIFICATIONPREFERENCES_TYPEPREFERENCESENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONPREFERENCES_ESCALATIONCONDITIONSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONPREFERENCES_ESCALATIONCONDITIONSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONPREFERENCES_CUSTOMFILTERSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONPREFERENCES_CUSTOMFILTERSENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONBATCH_METADATAENTRY']._loaded_options = None
  _globals['_NOTIFICATIONBATCH_METADATAENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONSCHEDULE_SCHEDULINGMETADATAENTRY']._loaded_options = None
  _globals['_NOTIFICATIONSCHEDULE_SCHEDULINGMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONSCHEDULE_FALLBACKOPTIONSENTRY']._loaded_options = None
  _globals['_NOTIFICATIONSCHEDULE_FALLBACKOPTIONSENTRY']._serialized_options = b'8\001'
  _globals['_SYSTEMALERT_ALERTMETADATAENTRY']._loaded_options = None
  _globals['_SYSTEMALERT_ALERTMETADATAENTRY']._serialized_options = b'8\001'
  _globals['_NOTIFICATIONTYPE']._serialized_start=4276
  _globals['_NOTIFICATIONTYPE']._serialized_end=4477
  _globals['_DELIVERYMETHOD']._serialized_start=4480
  _globals['_DELIVERYMETHOD']._serialized_end=4669
  _globals['_NOTIFICATION']._serialized_start=86
  _globals['_NOTIFICATION']._serialized_end=935
  _globals['_NOTIFICATION_METADATAENTRY']._serialized_start=773
  _globals['_NOTIFICATION_METADATAENTRY']._serialized_end=820
  _globals['_NOTIFICATION_RESPONSEOPTIONSENTRY']._serialized_start=822
  _globals['_NOTIFICATION_RESPONSEOPTIONSENTRY']._serialized_end=876
  _globals['_NOTIFICATION_ADAPTIVEPARAMETERSENTRY']._serialized_start=878
  _globals['_NOTIFICATION_ADAPTIVEPARAMETERSENTRY']._serialized_end=935
  _globals['_NOTIFICATIONSTATUS']._serialized_start=938
  _globals['_NOTIFICATIONSTATUS']._serialized_end=1378
  _globals['_NOTIFICATIONSTATUS_DELIVERYMETADATAENTRY']._serialized_start=1323
  _globals['_NOTIFICATIONSTATUS_DELIVERYMETADATAENTRY']._serialized_end=1378
  _globals['_NOTIFICATIONHISTORY']._serialized_start=1381
  _globals['_NOTIFICATIONHISTORY']._serialized_end=2149
  _globals['_NOTIFICATIONHISTORY_NOTIFICATIONCOUNTSENTRY']._serialized_start=1919
  _globals['_NOTIFICATIONHISTORY_NOTIFICATIONCOUNTSENTRY']._serialized_end=1976
  _globals['_NOTIFICATIONHISTORY_PRIORITYCOUNTSENTRY']._serialized_start=1978
  _globals['_NOTIFICATIONHISTORY_PRIORITYCOUNTSENTRY']._serialized_end=2031
  _globals['_NOTIFICATIONHISTORY_RESPONSETIMEAVERAGEENTRY']._serialized_start=2033
  _globals['_NOTIFICATIONHISTORY_RESPONSETIMEAVERAGEENTRY']._serialized_end=2091
  _globals['_NOTIFICATIONHISTORY_ENGAGEMENTMETRICSENTRY']._serialized_start=2093
  _globals['_NOTIFICATIONHISTORY_ENGAGEMENTMETRICSENTRY']._serialized_end=2149
  _globals['_NOTIFICATIONPREFERENCES']._serialized_start=2152
  _globals['_NOTIFICATIONPREFERENCES']._serialized_end=2989
  _globals['_NOTIFICATIONPREFERENCES_TYPEPREFERENCESENTRY']._serialized_start=2820
  _globals['_NOTIFICATIONPREFERENCES_TYPEPREFERENCESENTRY']._serialized_end=2874
  _globals['_NOTIFICATIONPREFERENCES_ESCALATIONCONDITIONSENTRY']._serialized_start=2876
  _globals['_NOTIFICATIONPREFERENCES_ESCALATIONCONDITIONSENTRY']._serialized_end=2935
  _globals['_NOTIFICATIONPREFERENCES_CUSTOMFILTERSENTRY']._serialized_start=2937
  _globals['_NOTIFICATIONPREFERENCES_CUSTOMFILTERSENTRY']._serialized_end=2989
  _globals['_NOTIFICATIONBATCH']._serialized_start=2992
  _globals['_NOTIFICATIONBATCH']._serialized_end=3411
  _globals['_NOTIFICATIONBATCH_METADATAENTRY']._serialized_start=773
  _globals['_NOTIFICATIONBATCH_METADATAENTRY']._serialized_end=820
  _globals['_NOTIFICATIONSCHEDULE']._serialized_start=3414
  _globals['_NOTIFICATIONSCHEDULE']._serialized_end=3974
  _globals['_NOTIFICATIONSCHEDULE_SCHEDULINGMETADATAENTRY']._serialized_start=3861
  _globals['_NOTIFICATIONSCHEDULE_SCHEDULINGMETADATAENTRY']._serialized_end=3918
  _globals['_NOTIFICATIONSCHEDULE_FALLBACKOPTIONSENTRY']._serialized_start=3920
  _globals['_NOTIFICATIONSCHEDULE_FALLBACKOPTIONSENTRY']._serialized_end=3974
  _globals['_SYSTEMALERT']._serialized_start=3977
  _globals['_SYSTEMALERT']._serialized_end=4273
  _globals['_SYSTEMALERT_ALERTMETADATAENTRY']._serialized_start=4221
  _globals['_SYSTEMALERT_ALERTMETADATAENTRY']._serialized_end=4273
  _globals['_NOTIFICATIONSERVICE']._serialized_start=4672
  _globals['_NOTIFICATIONSERVICE']._serialized_end=5166
# @@protoc_insertion_point(module_scope)
