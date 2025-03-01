# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: user_management.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "user_management.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import access_control_pb2 as access__control__pb2
from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x15user_management.proto\x12\x15seigr.user_management\x1a\x14\x61\x63\x63\x65ss_control.proto\x1a\x1fgoogle/protobuf/timestamp.proto"\xba\x05\n\x0bUserProfile\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12\x10\n\x08username\x18\x02 \x01(\t\x12\r\n\x05\x65mail\x18\x03 \x01(\t\x12-\n\x05roles\x18\x04 \x03(\x0e\x32\x1e.seigr.access_control.RoleType\x12<\n\x0e\x61\x63\x63ount_status\x18\x05 \x01(\x0e\x32$.seigr.user_management.AccountStatus\x12@\n\x0b\x61uth_method\x18\x06 \x01(\x0e\x32+.seigr.user_management.AuthenticationMethod\x12.\n\ncreated_at\x18\x07 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12.\n\nlast_login\x18\x08 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12Q\n\x10profile_metadata\x18\t \x03(\x0b\x32\x37.seigr.user_management.UserProfile.ProfileMetadataEntry\x12K\n\rsecurity_keys\x18\n \x03(\x0b\x32\x34.seigr.user_management.UserProfile.SecurityKeysEntry\x12\x16\n\x0erecovery_email\x18\x0b \x01(\t\x12\x14\n\x0cphone_number\x18\x0c \x01(\t\x12\x19\n\x11profile_image_url\x18\r \x01(\t\x12\x14\n\x0c\x64isplay_name\x18\x0e \x01(\t\x1a\x36\n\x14ProfileMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x33\n\x11SecurityKeysEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01"\xe7\x03\n\x0fUserPermissions\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12\x39\n\x0bpermissions\x18\x02 \x03(\x0e\x32$.seigr.access_control.PermissionType\x12\x44\n\x07\x63ontext\x18\x03 \x03(\x0b\x32\x33.seigr.user_management.UserPermissions.ContextEntry\x12*\n\x06\x65xpiry\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x16\n\x0e\x61\x64min_override\x18\x05 \x01(\x08\x12_\n\x15resource_restrictions\x18\x06 \x03(\x0b\x32@.seigr.user_management.UserPermissions.ResourceRestrictionsEntry\x12\x1a\n\x12\x61uthorized_devices\x18\x07 \x03(\t\x12\x14\n\x0c\x61\x63\x63\x65ss_zones\x18\x08 \x03(\t\x1a.\n\x0c\x43ontextEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a;\n\x19ResourceRestrictionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01"\xf2\x02\n\rUserAccessLog\x12\x0e\n\x06log_id\x18\x01 \x01(\t\x12\x0f\n\x07user_id\x18\x02 \x01(\t\x12\x35\n\x06\x61\x63tion\x18\x03 \x01(\x0e\x32%.seigr.user_management.UserActionType\x12-\n\ttimestamp\x18\x04 \x01(\x0b\x32\x1a.google.protobuf.Timestamp\x12\x13\n\x0bresource_id\x18\x05 \x01(\t\x12\x0f\n\x07success\x18\x06 \x01(\x08\x12\x44\n\x08metadata\x18\x07 \x03(\x0b\x32\x32.seigr.user_management.UserAccessLog.MetadataEntry\x12\x11\n\tdevice_id\x18\x08 \x01(\t\x12\x12\n\nsession_id\x18\t \x01(\t\x12\x16\n\x0e\x66\x61ilure_reason\x18\n \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xbd\x04\n\x0fUserPreferences\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12\x41\n\x0c\x61uth_methods\x18\x02 \x03(\x0e\x32+.seigr.user_management.AuthenticationMethod\x12\x1a\n\x12two_factor_enabled\x18\x03 \x01(\x08\x12\x1a\n\x12preferred_language\x18\x04 \x01(\t\x12\x1d\n\x15receive_notifications\x18\x05 \x01(\x08\x12\x65\n\x18permission_notifications\x18\x06 \x03(\x0b\x32\x43.seigr.user_management.UserPreferences.PermissionNotificationsEntry\x12W\n\x11ui_customizations\x18\x07 \x03(\x0b\x32<.seigr.user_management.UserPreferences.UiCustomizationsEntry\x12\x10\n\x08timezone\x18\x08 \x01(\t\x12\x19\n\x11\x64\x61rk_mode_enabled\x18\t \x01(\x08\x12\x19\n\x11\x66\x61vorite_features\x18\n \x03(\t\x1a>\n\x1cPermissionNotificationsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x37\n\x15UiCustomizationsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x1e\n\x0bUserRequest\x12\x0f\n\x07user_id\x18\x01 \x01(\t"0\n\x0cUserResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t*\xa7\x01\n\rAccountStatus\x12\x1c\n\x18\x41\x43\x43OUNT_STATUS_UNDEFINED\x10\x00\x12\x12\n\x0e\x41\x43\x43OUNT_ACTIVE\x10\x01\x12\x15\n\x11\x41\x43\x43OUNT_SUSPENDED\x10\x02\x12\x17\n\x13\x41\x43\x43OUNT_DEACTIVATED\x10\x03\x12 \n\x1c\x41\x43\x43OUNT_PENDING_VERIFICATION\x10\x04\x12\x12\n\x0e\x41\x43\x43OUNT_LOCKED\x10\x05*\x93\x01\n\x14\x41uthenticationMethod\x12\x12\n\x0e\x41UTH_UNDEFINED\x10\x00\x12\x11\n\rAUTH_PASSWORD\x10\x01\x12\x12\n\x0e\x41UTH_BIOMETRIC\x10\x02\x12\x0c\n\x08\x41UTH_OTP\x10\x03\x12\x0e\n\nAUTH_TOKEN\x10\x04\x12\x14\n\x10\x41UTH_CERTIFICATE\x10\x05\x12\x0c\n\x08\x41UTH_SSO\x10\x06*\x93\x01\n\x0eUserActionType\x12\x14\n\x10\x41\x43TION_UNDEFINED\x10\x00\x12\x10\n\x0c\x41\x43TION_LOGIN\x10\x01\x12\x11\n\rACTION_LOGOUT\x10\x02\x12\x0f\n\x0b\x41\x43TION_VIEW\x10\x03\x12\x0f\n\x0b\x41\x43TION_EDIT\x10\x04\x12\x11\n\rACTION_DELETE\x10\x05\x12\x11\n\rACTION_EXPORT\x10\x06\x32\xb9\x05\n\x15UserManagementService\x12\\\n\x11\x43reateUserProfile\x12".seigr.user_management.UserProfile\x1a#.seigr.user_management.UserResponse\x12\\\n\x11UpdateUserProfile\x12".seigr.user_management.UserProfile\x1a#.seigr.user_management.UserResponse\x12Z\n\x10\x46\x65tchUserProfile\x12".seigr.user_management.UserRequest\x1a".seigr.user_management.UserProfile\x12\x64\n\x15UpdateUserPermissions\x12&.seigr.user_management.UserPermissions\x1a#.seigr.user_management.UserResponse\x12Z\n\rLogUserAction\x12$.seigr.user_management.UserAccessLog\x1a#.seigr.user_management.UserResponse\x12`\n\x12GetUserPreferences\x12".seigr.user_management.UserRequest\x1a&.seigr.user_management.UserPreferences\x12\x64\n\x15UpdateUserPreferences\x12&.seigr.user_management.UserPreferences\x1a#.seigr.user_management.UserResponseb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "user_management_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_USERPROFILE_PROFILEMETADATAENTRY"]._loaded_options = None
    _globals["_USERPROFILE_PROFILEMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_USERPROFILE_SECURITYKEYSENTRY"]._loaded_options = None
    _globals["_USERPROFILE_SECURITYKEYSENTRY"]._serialized_options = b"8\001"
    _globals["_USERPERMISSIONS_CONTEXTENTRY"]._loaded_options = None
    _globals["_USERPERMISSIONS_CONTEXTENTRY"]._serialized_options = b"8\001"
    _globals["_USERPERMISSIONS_RESOURCERESTRICTIONSENTRY"]._loaded_options = None
    _globals["_USERPERMISSIONS_RESOURCERESTRICTIONSENTRY"]._serialized_options = b"8\001"
    _globals["_USERACCESSLOG_METADATAENTRY"]._loaded_options = None
    _globals["_USERACCESSLOG_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_USERPREFERENCES_PERMISSIONNOTIFICATIONSENTRY"]._loaded_options = None
    _globals["_USERPREFERENCES_PERMISSIONNOTIFICATIONSENTRY"]._serialized_options = b"8\001"
    _globals["_USERPREFERENCES_UICUSTOMIZATIONSENTRY"]._loaded_options = None
    _globals["_USERPREFERENCES_UICUSTOMIZATIONSENTRY"]._serialized_options = b"8\001"
    _globals["_ACCOUNTSTATUS"]._serialized_start = 2326
    _globals["_ACCOUNTSTATUS"]._serialized_end = 2493
    _globals["_AUTHENTICATIONMETHOD"]._serialized_start = 2496
    _globals["_AUTHENTICATIONMETHOD"]._serialized_end = 2643
    _globals["_USERACTIONTYPE"]._serialized_start = 2646
    _globals["_USERACTIONTYPE"]._serialized_end = 2793
    _globals["_USERPROFILE"]._serialized_start = 104
    _globals["_USERPROFILE"]._serialized_end = 802
    _globals["_USERPROFILE_PROFILEMETADATAENTRY"]._serialized_start = 695
    _globals["_USERPROFILE_PROFILEMETADATAENTRY"]._serialized_end = 749
    _globals["_USERPROFILE_SECURITYKEYSENTRY"]._serialized_start = 751
    _globals["_USERPROFILE_SECURITYKEYSENTRY"]._serialized_end = 802
    _globals["_USERPERMISSIONS"]._serialized_start = 805
    _globals["_USERPERMISSIONS"]._serialized_end = 1292
    _globals["_USERPERMISSIONS_CONTEXTENTRY"]._serialized_start = 1185
    _globals["_USERPERMISSIONS_CONTEXTENTRY"]._serialized_end = 1231
    _globals["_USERPERMISSIONS_RESOURCERESTRICTIONSENTRY"]._serialized_start = 1233
    _globals["_USERPERMISSIONS_RESOURCERESTRICTIONSENTRY"]._serialized_end = 1292
    _globals["_USERACCESSLOG"]._serialized_start = 1295
    _globals["_USERACCESSLOG"]._serialized_end = 1665
    _globals["_USERACCESSLOG_METADATAENTRY"]._serialized_start = 1618
    _globals["_USERACCESSLOG_METADATAENTRY"]._serialized_end = 1665
    _globals["_USERPREFERENCES"]._serialized_start = 1668
    _globals["_USERPREFERENCES"]._serialized_end = 2241
    _globals["_USERPREFERENCES_PERMISSIONNOTIFICATIONSENTRY"]._serialized_start = 2122
    _globals["_USERPREFERENCES_PERMISSIONNOTIFICATIONSENTRY"]._serialized_end = 2184
    _globals["_USERPREFERENCES_UICUSTOMIZATIONSENTRY"]._serialized_start = 2186
    _globals["_USERPREFERENCES_UICUSTOMIZATIONSENTRY"]._serialized_end = 2241
    _globals["_USERREQUEST"]._serialized_start = 2243
    _globals["_USERREQUEST"]._serialized_end = 2273
    _globals["_USERRESPONSE"]._serialized_start = 2275
    _globals["_USERRESPONSE"]._serialized_end = 2323
    _globals["_USERMANAGEMENTSERVICE"]._serialized_start = 2796
    _globals["_USERMANAGEMENTSERVICE"]._serialized_end = 3493
# @@protoc_insertion_point(module_scope)
