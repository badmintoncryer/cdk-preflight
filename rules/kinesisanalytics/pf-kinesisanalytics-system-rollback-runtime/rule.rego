package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-system-rollback-runtime", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationSystemRollbackConfiguration",
	sprintf("ApplicationSystemRollbackConfiguration is set on Studio runtime %v; CreateApplication fails with \"SystemRollbacksEnabled is not applicable to runtime environment : %v\"", [rt, rt]),
	"Drop ApplicationSystemRollbackConfiguration for Studio notebooks",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_has(_pf_kinlib_appcfg(name), "ApplicationSystemRollbackConfiguration")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_zeppelin(rt)
}
