package cdk_preflight

import rego.v1

_pf_cbgsm_unsupported := {"S3": "S3", "CODEPIPELINE": "CodePipeline"}

violation contains make_diag_full("pf-codebuild-git-submodules-config-git-sources-only", "ERROR", name,
	"Properties.Source.GitSubmodulesConfig",
	sprintf("GitSubmodulesConfig is set on a %s source, which is not a git checkout; CreateProject fails with \"Git submodules config is not supported for %s source\"", [t, _pf_cbgsm_unsupported[t]]),
	"Drop GitSubmodulesConfig, or build from a git-backed source",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-source.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	_pf_codebuildlib_has(_pf_codebuildlib_source(name), "GitSubmodulesConfig")
	t := _pf_codebuildlib_source_type(name)
	_pf_cbgsm_unsupported[t]
}
