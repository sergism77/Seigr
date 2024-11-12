# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: analytics.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import alerting_pb2 as alerting__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0f\x61nalytics.proto\x12\x05seigr\x1a\x0e\x61lerting.proto\"\xdc\x03\n\x17\x41nalyticsWorkflowConfig\x12\x13\n\x0bworkflow_id\x18\x01 \x01(\t\x12\x12\n\nmetric_ids\x18\x02 \x03(\t\x12$\n\nmodel_type\x18\x03 \x01(\x0e\x32\x10.seigr.ModelType\x12#\n\x1b\x65valuation_interval_seconds\x18\x04 \x01(\x05\x12\x1a\n\x12\x65nable_forecasting\x18\x05 \x01(\x08\x12\x12\n\ncreated_by\x18\x06 \x01(\t\x12\x12\n\ncreated_at\x18\x07 \x01(\t\x12K\n\x0f\x63onfig_metadata\x18\x08 \x03(\x0b\x32\x32.seigr.AnalyticsWorkflowConfig.ConfigMetadataEntry\x12M\n\x10model_parameters\x18\t \x03(\x0b\x32\x33.seigr.AnalyticsWorkflowConfig.ModelParametersEntry\x1a\x35\n\x13\x43onfigMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x36\n\x14ModelParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xee\x02\n\x10\x41nalyticsInsight\x12\x12\n\ninsight_id\x18\x01 \x01(\t\x12\x11\n\tmetric_id\x18\x02 \x01(\t\x12\x17\n\x0finsight_message\x18\x03 \x01(\t\x12\x15\n\rinsight_value\x18\x04 \x01(\x01\x12\x11\n\ttimestamp\x18\x05 \x01(\t\x12\x35\n\x10\x65scalation_level\x18\x06 \x01(\x0e\x32\x1b.seigr.AlertEscalationLevel\x12\x46\n\x10insight_metadata\x18\x07 \x03(\x0b\x32,.seigr.AnalyticsInsight.InsightMetadataEntry\x12\x12\n\nis_anomaly\x18\x08 \x01(\x08\x12\x14\n\x0cis_recurring\x18\t \x01(\x08\x12\x0f\n\x07\x63ontext\x18\n \x01(\t\x1a\x36\n\x14InsightMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xf5\x02\n\nDataMetric\x12\x11\n\tmetric_id\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x1f\n\x04type\x18\x03 \x01(\x0e\x32\x11.seigr.MetricType\x12\'\n\x08\x63\x61tegory\x18\x04 \x01(\x0e\x32\x15.seigr.MetricCategory\x12\r\n\x05value\x18\x05 \x01(\x01\x12\x0c\n\x04unit\x18\x06 \x01(\t\x12\x13\n\x0brecorded_at\x18\x07 \x01(\t\x12\x34\n\x12\x61ggregation_method\x18\x08 \x01(\x0e\x32\x18.seigr.AggregationMethod\x12\x18\n\x10source_component\x18\t \x01(\t\x12\x31\n\x08metadata\x18\n \x03(\x0b\x32\x1f.seigr.DataMetric.MetadataEntry\x12\x16\n\x0e\x66orecast_value\x18\x0b \x01(\t\x1a/\n\rMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc3\x03\n\x17\x41nalyticsAlertThreshold\x12\x14\n\x0cthreshold_id\x18\x01 \x01(\t\x12\'\n\x08\x63\x61tegory\x18\x02 \x01(\x0e\x32\x15.seigr.MetricCategory\x12\x17\n\x0fthreshold_value\x18\x03 \x01(\x01\x12&\n\x08severity\x18\x04 \x01(\x0e\x32\x14.seigr.AlertSeverity\x12\x35\n\x10\x65scalation_level\x18\x05 \x01(\x0e\x32\x1b.seigr.AlertEscalationLevel\x12\x11\n\tcondition\x18\x06 \x01(\t\x12\x1d\n\x15notification_channels\x18\x07 \x03(\t\x12I\n\x0e\x61lert_metadata\x18\x08 \x03(\x0b\x32\x31.seigr.AnalyticsAlertThreshold.AlertMetadataEntry\x12\x18\n\x10\x61\x63tion_on_breach\x18\t \x01(\t\x12$\n\x1cnotify_during_business_hours\x18\n \x01(\x08\x1a\x34\n\x12\x41lertMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xd5\x02\n\x11\x41nalyticsSettings\x12$\n\x1c\x61ggregation_interval_seconds\x18\x01 \x01(\x05\x12\x1b\n\x13\x64\x61ta_retention_days\x18\x02 \x01(\x05\x12\"\n\x1areal_time_alerting_enabled\x18\x03 \x01(\x08\x12!\n\x19\x61lert_evaluation_interval\x18\x04 \x01(\x05\x12\x32\n\nthresholds\x18\x05 \x03(\x0b\x32\x1e.seigr.AnalyticsAlertThreshold\x12I\n\x11settings_metadata\x18\x06 \x03(\x0b\x32..seigr.AnalyticsSettings.SettingsMetadataEntry\x1a\x37\n\x15SettingsMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc1\x03\n\x10\x41nalyticsSummary\x12\x12\n\nsummary_id\x18\x01 \x01(\t\x12\'\n\x08\x63\x61tegory\x18\x02 \x01(\x0e\x32\x15.seigr.MetricCategory\x12\x15\n\raverage_value\x18\x03 \x01(\x01\x12\x11\n\tmax_value\x18\x04 \x01(\x01\x12\x11\n\tmin_value\x18\x05 \x01(\x01\x12\x0f\n\x07std_dev\x18\x06 \x01(\x01\x12\x44\n\x0f\x66orecast_values\x18\x07 \x03(\x0b\x32+.seigr.AnalyticsSummary.ForecastValuesEntry\x12\r\n\x05trend\x18\x08 \x01(\t\x12\x16\n\x0esummary_period\x18\t \x01(\t\x12\x46\n\x10summary_metadata\x18\n \x03(\x0b\x32,.seigr.AnalyticsSummary.SummaryMetadataEntry\x1a\x35\n\x13\x46orecastValuesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a\x36\n\x14SummaryMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xc6\x02\n\x0f\x41nalyticsReport\x12\x11\n\treport_id\x18\x01 \x01(\t\x12\r\n\x05title\x18\x02 \x01(\t\x12\"\n\x07metrics\x18\x03 \x03(\x0b\x32\x11.seigr.DataMetric\x12)\n\x08insights\x18\x04 \x03(\x0b\x32\x17.seigr.AnalyticsInsight\x12\x14\n\x0cgenerated_by\x18\x05 \x01(\t\x12\x11\n\ttimestamp\x18\x06 \x01(\t\x12\x43\n\x0freport_metadata\x18\x07 \x03(\x0b\x32*.seigr.AnalyticsReport.ReportMetadataEntry\x12\x1d\n\x15\x63omparison_report_ids\x18\x08 \x03(\t\x1a\x35\n\x13ReportMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\x87\x03\n\x14WorkflowTriggerEvent\x12\x10\n\x08\x65vent_id\x18\x01 \x01(\t\x12\x13\n\x0bworkflow_id\x18\x02 \x01(\t\x12$\n\nmodel_type\x18\x03 \x01(\x0e\x32\x10.seigr.ModelType\x12&\n\x08severity\x18\x04 \x01(\x0e\x32\x14.seigr.AlertSeverity\x12\x35\n\x10\x65scalation_level\x18\x05 \x01(\x0e\x32\x1b.seigr.AlertEscalationLevel\x12\x14\n\x0c\x61\x63tion_taken\x18\x06 \x01(\t\x12\x11\n\ttimestamp\x18\x07 \x01(\t\x12\x46\n\x0e\x65vent_metadata\x18\x08 \x03(\x0b\x32..seigr.WorkflowTriggerEvent.EventMetadataEntry\x12\x1c\n\x14\x63onditional_triggers\x18\t \x03(\t\x1a\x34\n\x12\x45ventMetadataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01*\xab\x01\n\tModelType\x12\x18\n\x14MODEL_TYPE_UNDEFINED\x10\x00\x12\x0e\n\nREGRESSION\x10\x01\x12\x12\n\x0e\x43LASSIFICATION\x10\x02\x12\x15\n\x11\x41NOMALY_DETECTION\x10\x03\x12\x0f\n\x0bTIME_SERIES\x10\x04\x12\x0e\n\nCLUSTERING\x10\x05\x12\x17\n\x13PATTERN_RECOGNITION\x10\x06\x12\x0f\n\x0b\x46ORECASTING\x10\x07*\xa4\x01\n\x14\x41lertEscalationLevel\x12\x19\n\x15\x45SCALATION_LEVEL_NONE\x10\x00\x12\x18\n\x14\x45SCALATION_LEVEL_LOW\x10\x01\x12\x1d\n\x19\x45SCALATION_LEVEL_MODERATE\x10\x02\x12\x19\n\x15\x45SCALATION_LEVEL_HIGH\x10\x03\x12\x1d\n\x19\x45SCALATION_LEVEL_CRITICAL\x10\x04*v\n\x0eMetricCategory\x12\x1d\n\x19METRIC_CATEGORY_UNDEFINED\x10\x00\x12\x0f\n\x0bPERFORMANCE\x10\x01\x12\x0c\n\x08SECURITY\x10\x02\x12\t\n\x05USAGE\x10\x03\x12\x0f\n\x0bRELIABILITY\x10\x04\x12\n\n\x06\x43USTOM\x10\x05*c\n\nMetricType\x12\x19\n\x15METRIC_TYPE_UNDEFINED\x10\x00\x12\x0b\n\x07\x41VERAGE\x10\x01\x12\x0b\n\x07MAXIMUM\x10\x02\x12\x0b\n\x07MINIMUM\x10\x03\x12\n\n\x06MEDIAN\x10\x04\x12\x07\n\x03SUM\x10\x05*\x9a\x01\n\x11\x41ggregationMethod\x12 \n\x1c\x41GGREGATION_METHOD_UNDEFINED\x10\x00\x12\x11\n\rAGGREGATE_SUM\x10\x01\x12\x15\n\x11\x41GGREGATE_AVERAGE\x10\x02\x12\x13\n\x0f\x41GGREGATE_COUNT\x10\x03\x12\x11\n\rAGGREGATE_MAX\x10\x04\x12\x11\n\rAGGREGATE_MIN\x10\x05\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'analytics_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _ANALYTICSWORKFLOWCONFIG_CONFIGMETADATAENTRY._options = None
  _ANALYTICSWORKFLOWCONFIG_CONFIGMETADATAENTRY._serialized_options = b'8\001'
  _ANALYTICSWORKFLOWCONFIG_MODELPARAMETERSENTRY._options = None
  _ANALYTICSWORKFLOWCONFIG_MODELPARAMETERSENTRY._serialized_options = b'8\001'
  _ANALYTICSINSIGHT_INSIGHTMETADATAENTRY._options = None
  _ANALYTICSINSIGHT_INSIGHTMETADATAENTRY._serialized_options = b'8\001'
  _DATAMETRIC_METADATAENTRY._options = None
  _DATAMETRIC_METADATAENTRY._serialized_options = b'8\001'
  _ANALYTICSALERTTHRESHOLD_ALERTMETADATAENTRY._options = None
  _ANALYTICSALERTTHRESHOLD_ALERTMETADATAENTRY._serialized_options = b'8\001'
  _ANALYTICSSETTINGS_SETTINGSMETADATAENTRY._options = None
  _ANALYTICSSETTINGS_SETTINGSMETADATAENTRY._serialized_options = b'8\001'
  _ANALYTICSSUMMARY_FORECASTVALUESENTRY._options = None
  _ANALYTICSSUMMARY_FORECASTVALUESENTRY._serialized_options = b'8\001'
  _ANALYTICSSUMMARY_SUMMARYMETADATAENTRY._options = None
  _ANALYTICSSUMMARY_SUMMARYMETADATAENTRY._serialized_options = b'8\001'
  _ANALYTICSREPORT_REPORTMETADATAENTRY._options = None
  _ANALYTICSREPORT_REPORTMETADATAENTRY._serialized_options = b'8\001'
  _WORKFLOWTRIGGEREVENT_EVENTMETADATAENTRY._options = None
  _WORKFLOWTRIGGEREVENT_EVENTMETADATAENTRY._serialized_options = b'8\001'
  _MODELTYPE._serialized_start=3240
  _MODELTYPE._serialized_end=3411
  _ALERTESCALATIONLEVEL._serialized_start=3414
  _ALERTESCALATIONLEVEL._serialized_end=3578
  _METRICCATEGORY._serialized_start=3580
  _METRICCATEGORY._serialized_end=3698
  _METRICTYPE._serialized_start=3700
  _METRICTYPE._serialized_end=3799
  _AGGREGATIONMETHOD._serialized_start=3802
  _AGGREGATIONMETHOD._serialized_end=3956
  _ANALYTICSWORKFLOWCONFIG._serialized_start=43
  _ANALYTICSWORKFLOWCONFIG._serialized_end=519
  _ANALYTICSWORKFLOWCONFIG_CONFIGMETADATAENTRY._serialized_start=410
  _ANALYTICSWORKFLOWCONFIG_CONFIGMETADATAENTRY._serialized_end=463
  _ANALYTICSWORKFLOWCONFIG_MODELPARAMETERSENTRY._serialized_start=465
  _ANALYTICSWORKFLOWCONFIG_MODELPARAMETERSENTRY._serialized_end=519
  _ANALYTICSINSIGHT._serialized_start=522
  _ANALYTICSINSIGHT._serialized_end=888
  _ANALYTICSINSIGHT_INSIGHTMETADATAENTRY._serialized_start=834
  _ANALYTICSINSIGHT_INSIGHTMETADATAENTRY._serialized_end=888
  _DATAMETRIC._serialized_start=891
  _DATAMETRIC._serialized_end=1264
  _DATAMETRIC_METADATAENTRY._serialized_start=1217
  _DATAMETRIC_METADATAENTRY._serialized_end=1264
  _ANALYTICSALERTTHRESHOLD._serialized_start=1267
  _ANALYTICSALERTTHRESHOLD._serialized_end=1718
  _ANALYTICSALERTTHRESHOLD_ALERTMETADATAENTRY._serialized_start=1666
  _ANALYTICSALERTTHRESHOLD_ALERTMETADATAENTRY._serialized_end=1718
  _ANALYTICSSETTINGS._serialized_start=1721
  _ANALYTICSSETTINGS._serialized_end=2062
  _ANALYTICSSETTINGS_SETTINGSMETADATAENTRY._serialized_start=2007
  _ANALYTICSSETTINGS_SETTINGSMETADATAENTRY._serialized_end=2062
  _ANALYTICSSUMMARY._serialized_start=2065
  _ANALYTICSSUMMARY._serialized_end=2514
  _ANALYTICSSUMMARY_FORECASTVALUESENTRY._serialized_start=2405
  _ANALYTICSSUMMARY_FORECASTVALUESENTRY._serialized_end=2458
  _ANALYTICSSUMMARY_SUMMARYMETADATAENTRY._serialized_start=2460
  _ANALYTICSSUMMARY_SUMMARYMETADATAENTRY._serialized_end=2514
  _ANALYTICSREPORT._serialized_start=2517
  _ANALYTICSREPORT._serialized_end=2843
  _ANALYTICSREPORT_REPORTMETADATAENTRY._serialized_start=2790
  _ANALYTICSREPORT_REPORTMETADATAENTRY._serialized_end=2843
  _WORKFLOWTRIGGEREVENT._serialized_start=2846
  _WORKFLOWTRIGGEREVENT._serialized_end=3237
  _WORKFLOWTRIGGEREVENT_EVENTMETADATAENTRY._serialized_start=3185
  _WORKFLOWTRIGGEREVENT_EVENTMETADATAENTRY._serialized_end=3237
# @@protoc_insertion_point(module_scope)
