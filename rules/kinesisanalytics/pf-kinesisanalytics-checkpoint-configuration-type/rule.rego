package cdk_preflight

import rego.v1

_pf_kinck_keys := ["CheckpointingEnabled","CheckpointInterval","MinPauseBetweenCheckpoints"]

# DEFAULT does not mean "these values are ignored" — CreateApplication rejects
# the whole request when a value is present next to it.
violation contains make_diag_full("pf-kinesisanalytics-checkpoint-configuration-type", "ERROR", name,
	sprintf("Properties.ApplicationConfiguration.FlinkApplicationConfiguration.CheckpointConfiguration.%v", [k]),
	sprintf("CheckpointConfiguration sets %v while ConfigurationType is DEFAULT; CreateApplication fails with \"You are trying to provide custom values for the checkpoint configuration. Please use ConfigurationType as CUSTOM\"", [k]),
	"Set ConfigurationType to CUSTOM, or drop the custom values",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CheckpointConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	cfg := _pf_kinlib_obj(_pf_kinlib_flinkcfg(name), "CheckpointConfiguration")
	object.get(cfg, "ConfigurationType", "") == "DEFAULT"
	some k in _pf_kinck_keys
	_pf_kinlib_has(cfg, k)
}
