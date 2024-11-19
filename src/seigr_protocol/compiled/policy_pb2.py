# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: policy.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0cpolicy.proto\x12\x05seigr"\xac\x04\n\nPolicyRule\x12\x0f\n\x07rule_id\x18\x01 \x01(\t\x12(\n\trule_type\x18\x02 \x01(\x0e\x32\x15.seigr.PolicyRuleType\x12\x13\n\x0b\x64\x65scription\x18\x03 \x01(\t\x12(\n\x07\x61\x63tions\x18\x04 \x03(\x0e\x32\x17.seigr.GovernanceAction\x12\x12\n\ncreated_at\x18\x05 \x01(\t\x12\x15\n\rlast_modified\x18\x06 \x01(\t\x12>\n\x0frule_conditions\x18\x07 \x03(\x0b\x32%.seigr.PolicyRule.RuleConditionsEntry\x12\x44\n\x12penalty_conditions\x18\x08 \x03(\x0b\x32(.seigr.PolicyRule.PenaltyConditionsEntry\x12\x11\n\tis_active\x18\t \x01(\x08\x12:\n\rrule_metadata\x18\n \x03(\x0b\x32#.seigr.PolicyRule.RuleMetadataEntry\x1a\x35\n\x13RuleConditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x38\n\x16PenaltyConditionsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x33\n\x11RuleMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xc2\x02\n\x0f\x43omplianceAudit\x12\x10\n\x08\x61udit_id\x18\x01 \x01(\t\x12\x11\n\tpolicy_id\x18\x02 \x01(\t\x12\x0f\n\x07user_id\x18\x03 \x01(\t\x12\x11\n\ttimestamp\x18\x04 \x01(\t\x12\x19\n\x11\x63ompliance_status\x18\x05 \x01(\x08\x12\x1d\n\x15violation_description\x18\x06 \x01(\t\x12\x33\n\x12recommended_action\x18\x07 \x01(\x0e\x32\x17.seigr.GovernanceAction\x12\x41\n\x0e\x61udit_metadata\x18\x08 \x03(\x0b\x32).seigr.ComplianceAudit.AuditMetadataEntry\x1a\x34\n\x12\x41uditMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xd6\x02\n\x11PolicyEnforcement\x12\x11\n\tpolicy_id\x18\x01 \x01(\t\x12\x1b\n\x13target_component_id\x18\x02 \x01(\t\x12 \n\x05rules\x18\x03 \x03(\x0b\x32\x11.seigr.PolicyRule\x12\x1b\n\x13\x65nforce_immediately\x18\x04 \x01(\x08\x12\x19\n\x11\x65nforcement_level\x18\x05 \x01(\t\x12O\n\x14\x65nforcement_metadata\x18\x06 \x03(\x0b\x32\x31.seigr.PolicyEnforcement.EnforcementMetadataEntry\x12\x14\n\x0cinitiated_by\x18\x07 \x01(\t\x12\x14\n\x0cinitiated_at\x18\x08 \x01(\t\x1a:\n\x18\x45nforcementMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xd9\x02\n\x0cSystemPolicy\x12\x11\n\tpolicy_id\x18\x01 \x01(\t\x12\x13\n\x0bpolicy_name\x18\x02 \x01(\t\x12\x14\n\x0cpolicy_scope\x18\x03 \x01(\t\x12 \n\x05rules\x18\x04 \x03(\x0b\x32\x11.seigr.PolicyRule\x12\x11\n\tmandatory\x18\x05 \x01(\x08\x12@\n\x0fpolicy_metadata\x18\x06 \x03(\x0b\x32\'.seigr.SystemPolicy.PolicyMetadataEntry\x12\x12\n\ncreated_by\x18\x07 \x01(\t\x12\x12\n\ncreated_at\x18\x08 \x01(\t\x12\x13\n\x0bmodified_at\x18\t \x01(\t\x12 \n\x18\x61ssociated_compliance_id\x18\n \x01(\t\x1a\x35\n\x13PolicyMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01"\xd7\x02\n\x0fPolicyViolation\x12\x14\n\x0cviolation_id\x18\x01 \x01(\t\x12\x11\n\tpolicy_id\x18\x02 \x01(\t\x12\x0f\n\x07rule_id\x18\x03 \x01(\t\x12\x0f\n\x07user_id\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12\x30\n\x0fresponse_action\x18\x06 \x01(\x0e\x32\x17.seigr.GovernanceAction\x12\x19\n\x11resolution_status\x18\x07 \x01(\t\x12\x14\n\x0c\x65scalated_to\x18\x08 \x01(\t\x12I\n\x12violation_metadata\x18\t \x03(\x0b\x32-.seigr.PolicyViolation.ViolationMetadataEntry\x1a\x38\n\x16ViolationMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01">\n\x17PolicyDefinitionRequest\x12#\n\x06policy\x18\x01 \x01(\x0b\x32\x13.seigr.SystemPolicy"O\n\x18PolicyDefinitionResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x11\n\tpolicy_id\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t"B\n\x13PolicyUpdateRequest\x12+\n\x0eupdated_policy\x18\x01 \x01(\x0b\x32\x13.seigr.SystemPolicy"8\n\x14PolicyUpdateResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t"I\n\x18PolicyEnforcementRequest\x12-\n\x0b\x65nforcement\x18\x01 \x01(\x0b\x32\x18.seigr.PolicyEnforcement"U\n\x19PolicyEnforcementResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x16\n\x0e\x65nforcement_id\x18\x02 \x01(\t\x12\x0f\n\x07message\x18\x03 \x01(\t"<\n\x16\x43omplianceCheckRequest\x12\x0f\n\x07user_id\x18\x01 \x01(\t\x12\x11\n\tpolicy_id\x18\x02 \x01(\t"@\n\x17\x43omplianceCheckResponse\x12\x14\n\x0cis_compliant\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t"F\n\x19PolicyViolationLogRequest\x12)\n\tviolation\x18\x01 \x01(\x0b\x32\x16.seigr.PolicyViolation">\n\x1aPolicyViolationLogResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t"?\n\x16\x43omplianceAuditRequest\x12%\n\x05\x61udit\x18\x01 \x01(\x0b\x32\x16.seigr.ComplianceAudit";\n\x17\x43omplianceAuditResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\x0f\n\x07message\x18\x02 \x01(\t*\xd3\x01\n\x10GovernanceAction\x12\x14\n\x10\x41\x43TION_UNDEFINED\x10\x00\x12\x11\n\rACTION_REVIEW\x10\x01\x12\x13\n\x0f\x41\x43TION_ESCALATE\x10\x02\x12\x12\n\x0e\x41\x43TION_APPROVE\x10\x03\x12\x11\n\rACTION_REJECT\x10\x04\x12\x11\n\rACTION_NOTIFY\x10\x05\x12\x0f\n\x0b\x41\x43TION_WARN\x10\x06\x12\x18\n\x14\x41\x43TION_REVOKE_ACCESS\x10\x07\x12\x1c\n\x18\x41\x43TION_TERMINATE_PROCESS\x10\x08*\xc3\x01\n\x0ePolicyRuleType\x12\x19\n\x15POLICY_RULE_UNDEFINED\x10\x00\x12\x0f\n\x0b\x41\x43\x43\x45SS_RULE\x10\x01\x12\x17\n\x13\x44\x41TA_RETENTION_RULE\x10\x02\x12\x1c\n\x18RESOURCE_ALLOCATION_RULE\x10\x03\x12\x16\n\x12USER_ACTIVITY_RULE\x10\x04\x12\x10\n\x0cPRIVACY_RULE\x10\x05\x12\x13\n\x0f\x43OMPLIANCE_RULE\x10\x06\x12\x0f\n\x0b\x43USTOM_RULE\x10\x07\x32\x86\x04\n\x17PolicyManagementService\x12O\n\x0c\x43reatePolicy\x12\x1e.seigr.PolicyDefinitionRequest\x1a\x1f.seigr.PolicyDefinitionResponse\x12G\n\x0cUpdatePolicy\x12\x1a.seigr.PolicyUpdateRequest\x1a\x1b.seigr.PolicyUpdateResponse\x12R\n\rEnforcePolicy\x12\x1f.seigr.PolicyEnforcementRequest\x1a .seigr.PolicyEnforcementResponse\x12P\n\x0f\x43heckCompliance\x12\x1d.seigr.ComplianceCheckRequest\x1a\x1e.seigr.ComplianceCheckResponse\x12S\n\x0cLogViolation\x12 .seigr.PolicyViolationLogRequest\x1a!.seigr.PolicyViolationLogResponse\x12V\n\x15\x41uditPolicyCompliance\x12\x1d.seigr.ComplianceAuditRequest\x1a\x1e.seigr.ComplianceAuditResponseb\x06proto3'
)

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "policy_pb2", globals())
if _descriptor._USE_C_DESCRIPTORS == False:

    DESCRIPTOR._options = None
    _POLICYRULE_RULECONDITIONSENTRY._options = None
    _POLICYRULE_RULECONDITIONSENTRY._serialized_options = b"8\001"
    _POLICYRULE_PENALTYCONDITIONSENTRY._options = None
    _POLICYRULE_PENALTYCONDITIONSENTRY._serialized_options = b"8\001"
    _POLICYRULE_RULEMETADATAENTRY._options = None
    _POLICYRULE_RULEMETADATAENTRY._serialized_options = b"8\001"
    _COMPLIANCEAUDIT_AUDITMETADATAENTRY._options = None
    _COMPLIANCEAUDIT_AUDITMETADATAENTRY._serialized_options = b"8\001"
    _POLICYENFORCEMENT_ENFORCEMENTMETADATAENTRY._options = None
    _POLICYENFORCEMENT_ENFORCEMENTMETADATAENTRY._serialized_options = b"8\001"
    _SYSTEMPOLICY_POLICYMETADATAENTRY._options = None
    _SYSTEMPOLICY_POLICYMETADATAENTRY._serialized_options = b"8\001"
    _POLICYVIOLATION_VIOLATIONMETADATAENTRY._options = None
    _POLICYVIOLATION_VIOLATIONMETADATAENTRY._serialized_options = b"8\001"
    _GOVERNANCEACTION._serialized_start = 2770
    _GOVERNANCEACTION._serialized_end = 2981
    _POLICYRULETYPE._serialized_start = 2984
    _POLICYRULETYPE._serialized_end = 3179
    _POLICYRULE._serialized_start = 24
    _POLICYRULE._serialized_end = 580
    _POLICYRULE_RULECONDITIONSENTRY._serialized_start = 416
    _POLICYRULE_RULECONDITIONSENTRY._serialized_end = 469
    _POLICYRULE_PENALTYCONDITIONSENTRY._serialized_start = 471
    _POLICYRULE_PENALTYCONDITIONSENTRY._serialized_end = 527
    _POLICYRULE_RULEMETADATAENTRY._serialized_start = 529
    _POLICYRULE_RULEMETADATAENTRY._serialized_end = 580
    _COMPLIANCEAUDIT._serialized_start = 583
    _COMPLIANCEAUDIT._serialized_end = 905
    _COMPLIANCEAUDIT_AUDITMETADATAENTRY._serialized_start = 853
    _COMPLIANCEAUDIT_AUDITMETADATAENTRY._serialized_end = 905
    _POLICYENFORCEMENT._serialized_start = 908
    _POLICYENFORCEMENT._serialized_end = 1250
    _POLICYENFORCEMENT_ENFORCEMENTMETADATAENTRY._serialized_start = 1192
    _POLICYENFORCEMENT_ENFORCEMENTMETADATAENTRY._serialized_end = 1250
    _SYSTEMPOLICY._serialized_start = 1253
    _SYSTEMPOLICY._serialized_end = 1598
    _SYSTEMPOLICY_POLICYMETADATAENTRY._serialized_start = 1545
    _SYSTEMPOLICY_POLICYMETADATAENTRY._serialized_end = 1598
    _POLICYVIOLATION._serialized_start = 1601
    _POLICYVIOLATION._serialized_end = 1944
    _POLICYVIOLATION_VIOLATIONMETADATAENTRY._serialized_start = 1888
    _POLICYVIOLATION_VIOLATIONMETADATAENTRY._serialized_end = 1944
    _POLICYDEFINITIONREQUEST._serialized_start = 1946
    _POLICYDEFINITIONREQUEST._serialized_end = 2008
    _POLICYDEFINITIONRESPONSE._serialized_start = 2010
    _POLICYDEFINITIONRESPONSE._serialized_end = 2089
    _POLICYUPDATEREQUEST._serialized_start = 2091
    _POLICYUPDATEREQUEST._serialized_end = 2157
    _POLICYUPDATERESPONSE._serialized_start = 2159
    _POLICYUPDATERESPONSE._serialized_end = 2215
    _POLICYENFORCEMENTREQUEST._serialized_start = 2217
    _POLICYENFORCEMENTREQUEST._serialized_end = 2290
    _POLICYENFORCEMENTRESPONSE._serialized_start = 2292
    _POLICYENFORCEMENTRESPONSE._serialized_end = 2377
    _COMPLIANCECHECKREQUEST._serialized_start = 2379
    _COMPLIANCECHECKREQUEST._serialized_end = 2439
    _COMPLIANCECHECKRESPONSE._serialized_start = 2441
    _COMPLIANCECHECKRESPONSE._serialized_end = 2505
    _POLICYVIOLATIONLOGREQUEST._serialized_start = 2507
    _POLICYVIOLATIONLOGREQUEST._serialized_end = 2577
    _POLICYVIOLATIONLOGRESPONSE._serialized_start = 2579
    _POLICYVIOLATIONLOGRESPONSE._serialized_end = 2641
    _COMPLIANCEAUDITREQUEST._serialized_start = 2643
    _COMPLIANCEAUDITREQUEST._serialized_end = 2706
    _COMPLIANCEAUDITRESPONSE._serialized_start = 2708
    _COMPLIANCEAUDITRESPONSE._serialized_end = 2767
    _POLICYMANAGEMENTSERVICE._serialized_start = 3182
    _POLICYMANAGEMENTSERVICE._serialized_end = 3700
# @@protoc_insertion_point(module_scope)
