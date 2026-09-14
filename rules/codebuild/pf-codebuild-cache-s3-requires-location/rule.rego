package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codebuild-cache-s3-requires-location", "ERROR", name,
	"Properties.Cache",
	"Cache.Type is S3 but no Location is set; CreateProject fails with \"Invalid cache: location must be a valid S3 bucket, followed by slash and the prefix\"",
	"Set Cache.Location to bucket/prefix",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-codebuild-project-projectcache.html") if {
	some name in resources_of_type("AWS::CodeBuild::Project")
	c := _pf_codebuildlib_cache(name)
	_pf_codebuildlib_str(c, "Type") == "S3"
	not _pf_codebuildlib_has(c, "Location")
}
