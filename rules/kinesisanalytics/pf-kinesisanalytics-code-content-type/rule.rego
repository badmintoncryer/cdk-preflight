package cdk_preflight

import rego.v1

_pf_kincct_url := "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationCodeConfiguration.html"

_pf_kincct_type(name) := ct if {
	ct := resolve(name, "Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContentType")
	is_string(ct)
}

violation contains make_diag_full("pf-kinesisanalytics-code-content-type", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContentType",
	sprintf("runtime %v only accepts ZIPFILE code but CodeContentType is %v; CreateApplication fails with \"Flink application only supports ZIPFILE for application code content\"", [rt, ct]),
	"Package the application as a ZIPFILE in Amazon S3",
	_pf_kincct_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_flink(rt)
	ct := _pf_kincct_type(name)
	ct != "ZIPFILE"
}

violation contains make_diag_full("pf-kinesisanalytics-code-content-type", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContentType",
	sprintf("Studio runtime %v only accepts PLAINTEXT code but CodeContentType is %v; CreateApplication fails with \"Zeppelin application only supports PLAINTEXT for application code content\"", [rt, ct]),
	"Pass the notebook as PLAINTEXT",
	_pf_kincct_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	rt := _pf_kinlib_runtime(name)
	_pf_kinlib_zeppelin(rt)
	ct := _pf_kincct_type(name)
	ct != "PLAINTEXT"
}
