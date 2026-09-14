package cdk_preflight

import rego.v1

_pf_cbrbs_unsupported := {"S3", "NO_SOURCE", "CODEPIPELINE", "CODECOMMIT"}

violation contains make_diag_full("pf-codebuild-report-build-status-provider", "ERROR", name,
	"Properties.Source.ReportBuildStatus",
	sprintf("ReportBuildStatus is set on a %s source; only GitHub, GitHub Enterprise, GitLab and Bitbucket take build status back, and CreateProject fails with \"Source type %s does not support ReportBuildStatus\" even when the value is false", [t, t]),
	"Drop ReportBuildStatus, or build from GitHub, GitHub Enterprise, GitLab or Bitbucket",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	s := _pf_codebuildlib_source(name)
	_pf_codebuildlib_has(s, "ReportBuildStatus")
	t := _pf_codebuildlib_source_type(name)
	t in _pf_cbrbs_unsupported
}
