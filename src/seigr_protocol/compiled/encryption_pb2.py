# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: encryption.proto
# Protobuf Python Version: 5.29.2
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 5, 29, 2, "", "encryption.proto"
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x10\x65ncryption.proto\x12\x10seigr.encryption\x1a\x0c\x63ommon.proto"\x8c\x03\n\x10\x45ncryptionPolicy\x12\x11\n\tpolicy_id\x18\x01 \x01(\t\x12\x13\n\x0bpolicy_name\x18\x02 \x01(\t\x12\x39\n\x0f\x65ncryption_type\x18\x03 \x01(\x0e\x32 .seigr.encryption.EncryptionType\x12\x1b\n\x13\x63ompliance_standard\x18\x04 \x01(\t\x12\x42\n\x08metadata\x18\x05 \x03(\x0b\x32\x30.seigr.encryption.EncryptionPolicy.MetadataEntry\x12\x12\n\ncreated_at\x18\x06 \x01(\t\x12\x12\n\nupdated_at\x18\x07 \x01(\t\x12\x1c\n\x14\x61pplicable_resources\x18\x08 \x03(\t\x12 \n\x18\x65nforce_integrity_checks\x18\t \x01(\x08\x12\x1b\n\x13\x61pproved_algorithms\x18\n \x03(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc3\x02\n\x0cSymmetricKey\x12\x0e\n\x06key_id\x18\x01 \x01(\t\x12\x0b\n\x03key\x18\x02 \x01(\x0c\x12\x0c\n\x04salt\x18\x03 \x01(\x0c\x12\x11\n\talgorithm\x18\x04 \x01(\t\x12\x12\n\ncreated_at\x18\x05 \x01(\t\x12\x15\n\rexpiration_at\x18\x06 \x01(\t\x12+\n\x06status\x18\x07 \x01(\x0e\x32\x1b.seigr.encryption.KeyStatus\x12\x19\n\x11rotation_schedule\x18\x08 \x01(\t\x12\x11\n\tcustodian\x18\t \x01(\t\x12>\n\x08metadata\x18\n \x03(\x0b\x32,.seigr.encryption.SymmetricKey.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xb2\x02\n\x11\x41symmetricKeyPair\x12\x13\n\x0bkey_pair_id\x18\x01 \x01(\t\x12\x12\n\npublic_key\x18\x02 \x01(\x0c\x12\x13\n\x0bprivate_key\x18\x03 \x01(\x0c\x12\x11\n\talgorithm\x18\x04 \x01(\t\x12\x12\n\ncreated_at\x18\x05 \x01(\t\x12\x15\n\rexpiration_at\x18\x06 \x01(\t\x12+\n\x06status\x18\x07 \x01(\x0e\x32\x1b.seigr.encryption.KeyStatus\x12\x43\n\x08metadata\x18\x08 \x03(\x0b\x32\x31.seigr.encryption.AsymmetricKeyPair.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\x93\x02\n\rEncryptedData\x12\x0f\n\x07\x64\x61ta_id\x18\x01 \x01(\t\x12\x12\n\nciphertext\x18\x02 \x01(\x0c\x12\n\n\x02iv\x18\x03 \x01(\x0c\x12\x0e\n\x06key_id\x18\x04 \x01(\t\x12\x39\n\x0f\x65ncryption_type\x18\x05 \x01(\x0e\x32 .seigr.encryption.EncryptionType\x12\x14\n\x0c\x65ncrypted_at\x18\x06 \x01(\t\x12?\n\x08metadata\x18\x07 \x03(\x0b\x32-.seigr.encryption.EncryptedData.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xe9\x01\n\x10\x44igitalSignature\x12\x14\n\x0csignature_id\x18\x01 \x01(\t\x12\x11\n\tsigner_id\x18\x02 \x01(\t\x12\x11\n\tsignature\x18\x03 \x01(\x0c\x12\x11\n\talgorithm\x18\x04 \x01(\t\x12\x11\n\tsigned_at\x18\x05 \x01(\t\x12\x42\n\x08metadata\x18\x06 \x03(\x0b\x32\x30.seigr.encryption.DigitalSignature.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc8\x02\n\x19\x43ryptographicOperationLog\x12\x14\n\x0coperation_id\x18\x01 \x01(\t\x12\x44\n\x0eoperation_type\x18\x02 \x01(\x0e\x32,.seigr.encryption.CryptographicOperationType\x12\x14\n\x0cperformed_by\x18\x03 \x01(\t\x12\x0e\n\x06key_id\x18\x04 \x01(\t\x12\x18\n\x10operation_status\x18\x05 \x01(\t\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12K\n\x08metadata\x18\x07 \x03(\x0b\x32\x39.seigr.encryption.CryptographicOperationLog.MetadataEntry\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xa6\x03\n\x18IntegrityVerificationLog\x12\x17\n\x0fverification_id\x18\x01 \x01(\t\x12\x1c\n\x14verified_resource_id\x18\x02 \x01(\t\x12\x0e\n\x06key_id\x18\x03 \x01(\t\x12\x1b\n\x13verification_status\x18\x04 \x01(\t\x12\x1e\n\x16verification_algorithm\x18\x05 \x01(\t\x12\x37\n\x16verification_timestamp\x18\x06 \x01(\x0b\x32\x17.seigr.common.Timestamp\x12\x13\n\x0bverifier_id\x18\x07 \x01(\t\x12\x16\n\x0e\x66\x61ilure_reason\x18\x08 \x01(\t\x12\x63\n\x15verification_metadata\x18\t \x03(\x0b\x32\x44.seigr.encryption.IntegrityVerificationLog.VerificationMetadataEntry\x1a;\n\x19VerificationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xa6\x01\n\tKeyStatus\x12\x18\n\x14KEY_STATUS_UNDEFINED\x10\x00\x12\x15\n\x11KEY_STATUS_ACTIVE\x10\x01\x12\x17\n\x13KEY_STATUS_INACTIVE\x10\x02\x12\x16\n\x12KEY_STATUS_REVOKED\x10\x03\x12\x1f\n\x1bKEY_STATUS_PENDING_ROTATION\x10\x04\x12\x16\n\x12KEY_STATUS_EXPIRED\x10\x05*\xac\x01\n\x0e\x45ncryptionType\x12\x1d\n\x19\x45NCRYPTION_TYPE_UNDEFINED\x10\x00\x12\x1d\n\x19\x45NCRYPTION_TYPE_SYMMETRIC\x10\x01\x12\x1e\n\x1a\x45NCRYPTION_TYPE_ASYMMETRIC\x10\x02\x12\x1a\n\x16\x45NCRYPTION_TYPE_HYBRID\x10\x03\x12 \n\x1c\x45NCRYPTION_TYPE_QUANTUM_SAFE\x10\x04*\xfa\x01\n\x1a\x43ryptographicOperationType\x12\x1c\n\x18OPERATION_TYPE_UNDEFINED\x10\x00\x12\x1d\n\x19OPERATION_TYPE_ENCRYPTION\x10\x01\x12\x1d\n\x19OPERATION_TYPE_DECRYPTION\x10\x02\x12\x1a\n\x16OPERATION_TYPE_SIGNING\x10\x03\x12\x1f\n\x1bOPERATION_TYPE_VERIFICATION\x10\x04\x12\x1f\n\x1bOPERATION_TYPE_KEY_ROTATION\x10\x05\x12"\n\x1eOPERATION_TYPE_INTEGRITY_CHECK\x10\x06\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "encryption_pb2", _globals)
if not _descriptor._USE_C_DESCRIPTORS:
    DESCRIPTOR._loaded_options = None
    _globals["_ENCRYPTIONPOLICY_METADATAENTRY"]._loaded_options = None
    _globals["_ENCRYPTIONPOLICY_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_SYMMETRICKEY_METADATAENTRY"]._loaded_options = None
    _globals["_SYMMETRICKEY_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ASYMMETRICKEYPAIR_METADATAENTRY"]._loaded_options = None
    _globals["_ASYMMETRICKEYPAIR_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_ENCRYPTEDDATA_METADATAENTRY"]._loaded_options = None
    _globals["_ENCRYPTEDDATA_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_DIGITALSIGNATURE_METADATAENTRY"]._loaded_options = None
    _globals["_DIGITALSIGNATURE_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_CRYPTOGRAPHICOPERATIONLOG_METADATAENTRY"]._loaded_options = None
    _globals["_CRYPTOGRAPHICOPERATIONLOG_METADATAENTRY"]._serialized_options = b"8\001"
    _globals["_INTEGRITYVERIFICATIONLOG_VERIFICATIONMETADATAENTRY"]._loaded_options = None
    _globals["_INTEGRITYVERIFICATIONLOG_VERIFICATIONMETADATAENTRY"]._serialized_options = b"8\001"
    _globals["_KEYSTATUS"]._serialized_start = 2357
    _globals["_KEYSTATUS"]._serialized_end = 2523
    _globals["_ENCRYPTIONTYPE"]._serialized_start = 2526
    _globals["_ENCRYPTIONTYPE"]._serialized_end = 2698
    _globals["_CRYPTOGRAPHICOPERATIONTYPE"]._serialized_start = 2701
    _globals["_CRYPTOGRAPHICOPERATIONTYPE"]._serialized_end = 2951
    _globals["_ENCRYPTIONPOLICY"]._serialized_start = 53
    _globals["_ENCRYPTIONPOLICY"]._serialized_end = 449
    _globals["_ENCRYPTIONPOLICY_METADATAENTRY"]._serialized_start = 402
    _globals["_ENCRYPTIONPOLICY_METADATAENTRY"]._serialized_end = 449
    _globals["_SYMMETRICKEY"]._serialized_start = 452
    _globals["_SYMMETRICKEY"]._serialized_end = 775
    _globals["_SYMMETRICKEY_METADATAENTRY"]._serialized_start = 402
    _globals["_SYMMETRICKEY_METADATAENTRY"]._serialized_end = 449
    _globals["_ASYMMETRICKEYPAIR"]._serialized_start = 778
    _globals["_ASYMMETRICKEYPAIR"]._serialized_end = 1084
    _globals["_ASYMMETRICKEYPAIR_METADATAENTRY"]._serialized_start = 402
    _globals["_ASYMMETRICKEYPAIR_METADATAENTRY"]._serialized_end = 449
    _globals["_ENCRYPTEDDATA"]._serialized_start = 1087
    _globals["_ENCRYPTEDDATA"]._serialized_end = 1362
    _globals["_ENCRYPTEDDATA_METADATAENTRY"]._serialized_start = 402
    _globals["_ENCRYPTEDDATA_METADATAENTRY"]._serialized_end = 449
    _globals["_DIGITALSIGNATURE"]._serialized_start = 1365
    _globals["_DIGITALSIGNATURE"]._serialized_end = 1598
    _globals["_DIGITALSIGNATURE_METADATAENTRY"]._serialized_start = 402
    _globals["_DIGITALSIGNATURE_METADATAENTRY"]._serialized_end = 449
    _globals["_CRYPTOGRAPHICOPERATIONLOG"]._serialized_start = 1601
    _globals["_CRYPTOGRAPHICOPERATIONLOG"]._serialized_end = 1929
    _globals["_CRYPTOGRAPHICOPERATIONLOG_METADATAENTRY"]._serialized_start = 402
    _globals["_CRYPTOGRAPHICOPERATIONLOG_METADATAENTRY"]._serialized_end = 449
    _globals["_INTEGRITYVERIFICATIONLOG"]._serialized_start = 1932
    _globals["_INTEGRITYVERIFICATIONLOG"]._serialized_end = 2354
    _globals["_INTEGRITYVERIFICATIONLOG_VERIFICATIONMETADATAENTRY"]._serialized_start = 2295
    _globals["_INTEGRITYVERIFICATIONLOG_VERIFICATIONMETADATAENTRY"]._serialized_end = 2354
# @@protoc_insertion_point(module_scope)
