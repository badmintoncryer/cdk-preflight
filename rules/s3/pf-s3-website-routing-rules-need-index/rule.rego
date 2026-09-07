package cdk_preflight

import rego.v1

_pf_s3wri_fix := "Add WebsiteConfiguration.IndexDocument next to the routing rules"

_pf_s3wri_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-routingrule.html"

_pf_s3wri_has_index(name) if {
	is_string(resolve(name, "Properties.WebsiteConfiguration.IndexDocument"))
}

violation contains make_diag_full("pf-s3-website-routing-rules-need-index", "ERROR", name,
	"Properties.WebsiteConfiguration.RoutingRules",
	"the website configuration declares RoutingRules without an IndexDocument; PutBucketWebsite requires one",
	_pf_s3wri_fix, _pf_s3wri_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	count(flatten_list(name, "Properties.WebsiteConfiguration.RoutingRules")) > 0
	not _pf_s3wri_has_index(name)
}
