package cdk_preflight

import rego.v1

_pf_kinamr_url := "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CreateApplication.html"

_pf_kinamr_interactive(name) if resolve(name, "Properties.ApplicationMode") == "INTERACTIVE"

violation contains make_diag_full("pf-kinesisanalytics-application-mode-runtime", "ERROR", name,
	"Properties.ApplicationMode",
	sprintf("runtime %v is a Studio notebook and needs ApplicationMode INTERACTIVE; CreateApplication fails with \"ApplicationMode ... is not applicable to runtime environment : %v\"", [rt, rt]),
	"Set ApplicationMode to INTERACTIVE for ZEPPELIN-FLINK runtimes",
	_pf_kinamr_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_zeppelin(rt)
	not _pf_kinamr_interactive(name)
}

violation contains make_diag_full("pf-kinesisanalytics-application-mode-runtime", "ERROR", name,
	"Properties.ApplicationMode",
	sprintf("ApplicationMode INTERACTIVE is a Studio notebook mode but the runtime is %v; CreateApplication fails with \"ApplicationMode 'INTERACTIVE' is not applicable to runtime environment : %v\"", [rt, rt]),
	"Use STREAMING (or leave ApplicationMode out) for FLINK runtimes",
	_pf_kinamr_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_flink(rt)
	_pf_kinamr_interactive(name)
}
