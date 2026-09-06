package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-snapshot-runtime", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationSnapshotConfiguration",
	sprintf("ApplicationSnapshotConfiguration is set on Studio runtime %v; CreateApplication fails with \"SnapshotsEnabled is not applicable to runtime environment : %v\"", [rt, rt]),
	"Drop ApplicationSnapshotConfiguration for Studio notebooks",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_has(_pf_kinlib_appcfg(name), "ApplicationSnapshotConfiguration")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_zeppelin(rt)
}
