package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-cache-location-ignored-for-local", "ERROR", name,
	"Properties.Cache.Modes",
	"LOCAL_SOURCE_CACHE caches the checkout, but Source.Type is NO_SOURCE; CreateProject fails with \"Cache mode LOCAL_SOURCE_CACHE is not available for source type NO_SOURCE\"",
	"Drop LOCAL_SOURCE_CACHE, or give the project a source to check out",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectcache.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	some m in object.get(_pf_codebuildlib_cache(name), "Modes", [])
	m == "LOCAL_SOURCE_CACHE"
	_pf_codebuildlib_source_type(name) == "NO_SOURCE"
}
