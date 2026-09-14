package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-logs-s3-requires-location", "ERROR", name,
	"Properties.LogsConfig.S3Logs",
	"S3Logs.Status is ENABLED but no Location is set; CreateProject fails with \"Invalid logsConfig: s3Logs location must be provided if status is 'ENABLED'\"",
	"Set S3Logs.Location to bucket/prefix, or leave S3Logs.Status at DISABLED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-s3logsconfig.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	s3 := _pf_codebuildlib_obj(_pf_codebuildlib_obj(_pf_codebuildlib_props(name), "LogsConfig"), "S3Logs")
	_pf_codebuildlib_str(s3, "Status") == "ENABLED"
	not _pf_codebuildlib_has(s3, "Location")
}
