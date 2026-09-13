package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-cache-local-requires-modes", "ERROR", name,
	"Properties.Cache",
	"Cache.Type is LOCAL but no Modes are listed; CreateProject fails with \"At least one mode must be provided for cache type: LOCAL\"",
	"List at least one of LOCAL_SOURCE_CACHE, LOCAL_DOCKER_LAYER_CACHE or LOCAL_CUSTOM_CACHE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectcache.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	c := _pf_codebuildlib_cache(name)
	_pf_codebuildlib_str(c, "Type") == "LOCAL"
	object.get(c, "Modes", []) == []
}
