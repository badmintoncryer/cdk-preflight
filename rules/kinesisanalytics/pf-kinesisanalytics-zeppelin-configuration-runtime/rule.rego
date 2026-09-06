package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-kinesisanalytics-zeppelin-configuration-runtime", "ERROR", name,
	"Properties.ApplicationConfiguration.ZeppelinApplicationConfiguration",
	sprintf("ZeppelinApplicationConfiguration is set on runtime %v; CreateApplication fails with \"ZeppelinApplicationConfiguration is not applicable to runtime environment : %v\"", [rt, rt]),
	"Use a ZEPPELIN-FLINK runtime for Studio notebooks, or drop the Zeppelin configuration",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_has(_pf_kinlib_appcfg(name), "ZeppelinApplicationConfiguration")
	rt := _pf_kinlib_runtime(name)
	not _pf_kinlib_zeppelin(rt)
}
