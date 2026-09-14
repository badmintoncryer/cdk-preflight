package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-reportgroup-s3-export-requires-destination", "ERROR", name,
	"Properties.ExportConfig",
	"ExportConfigType is S3 but no S3Destination is set; CreateReportGroup fails with \"S3 export config is required when export config type is S3\"",
	"Set ExportConfig.S3Destination to the bucket the reports are exported to",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-reportgroup-reportexportconfig.html") if {
	some name in resources_of_type("AWS::CodeBuild::ReportGroup")
	ec := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "ExportConfig")
	_pf_codebuildlib_str(ec, "ExportConfigType") == "S3"
	not _pf_codebuildlib_has(ec, "S3Destination")
}
