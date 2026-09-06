package cdk_preflight

import rego.v1

_pf_kinccm_url := "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CodeContent.html"

_pf_kinccm_content(name) := cc if {
	cc := _pf_kinlib_obj(_pf_kinlib_obj(_pf_kinlib_appcfg(name), "ApplicationCodeConfiguration"), "CodeContent")
}

_pf_kinccm_any(cc) if {
	some k in ["S3ContentLocation", "TextContent", "ZipFileContent"]
	_pf_kinlib_has(cc, k)
}

violation contains make_diag_full("pf-kinesisanalytics-code-content-member", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContent.TextContent",
	"CodeContentType is ZIPFILE but CodeContent carries TextContent; CreateApplication fails with \"You have provided ZIPFILE code content type, but have provided other code contents. Please specify either ZipFileContent or S3ContentLocation.\"",
	"Point CodeContent at S3ContentLocation (or ZipFileContent) for ZIPFILE code",
	_pf_kinccm_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	resolve(name, "Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContentType") == "ZIPFILE"
	_pf_kinlib_has(_pf_kinccm_content(name), "TextContent")
}

violation contains make_diag_full("pf-kinesisanalytics-code-content-member", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContent",
	"CodeContent is empty; CreateApplication fails with \"You have provided an empty CodeContent. Please provide a valid CodeContent.\"",
	"Set one of S3ContentLocation, TextContent or ZipFileContent",
	_pf_kinccm_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	cc := _pf_kinccm_content(name)
	not _pf_kinccm_any(cc)
}
