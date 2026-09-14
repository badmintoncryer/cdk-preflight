package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-reportgroup-no-export-forbids-destination", "ERROR", name,
	"Properties.ExportConfig.S3Destination",
	"ExportConfigType is NO_EXPORT but an S3Destination is set; CreateReportGroup fails with \"S3 export config should not be specified when export config type is NO_EXPORT\"",
	"Drop S3Destination, or set ExportConfigType to S3",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-reportgroup-reportexportconfig.html") if {
	some name in resources_of_type("AWS::CodeBuild::ReportGroup")
	ec := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "ExportConfig")
	_pf_codebuildlib_str(ec, "ExportConfigType") == "NO_EXPORT"
	_pf_codebuildlib_has(ec, "S3Destination")
}
