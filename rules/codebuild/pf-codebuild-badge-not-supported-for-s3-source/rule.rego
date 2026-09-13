package cdk_preflight

import rego.v1

_pf_cbbadge_unsupported := {"S3": "Build badges are not supported for S3 source", "NO_SOURCE": "Build badges are not supported for projects with no source"}

violation contains make_diag_full("pf-codebuild-badge-not-supported-for-s3-source", "ERROR", name,
	"Properties.BadgeEnabled",
	sprintf("BadgeEnabled is true on a %s source; CreateProject fails with \"%s\"", [t, _pf_cbbadge_unsupported[t]]),
	"Drop BadgeEnabled, or build from a source provider that serves badges",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_codebuildlib_true(object.get(_pf_codebuildlib_props(name), "BadgeEnabled", null))
	t := _pf_codebuildlib_source_type(name)
	_pf_cbbadge_unsupported[t]
}
