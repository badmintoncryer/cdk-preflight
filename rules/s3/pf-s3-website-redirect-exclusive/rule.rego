package cdk_preflight

import rego.v1

# RedirectAllRequestsTo redirects the whole site, so S3 rejects any sibling
# website setting alongside it.
violation contains make_diag_full("pf-s3-website-redirect-exclusive", "ERROR", name,
	sprintf("Properties.WebsiteConfiguration.%s", [k]),
	sprintf("WebsiteConfiguration combines RedirectAllRequestsTo with %s; S3 rejects it with \"[IndexDocument, ErrorDocument, RoutingRules] should not be specified if RedirectAllRequestsTo is specified\"", [k]),
	"Keep RedirectAllRequestsTo alone, or drop it and configure the website with IndexDocument/ErrorDocument/RoutingRules",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-websiteconfiguration.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	wc := resolve(name, "Properties.WebsiteConfiguration")
	is_object(wc)
	object.get(wc, "RedirectAllRequestsTo", "__pf_absent") != "__pf_absent"
	some k in {"IndexDocument", "ErrorDocument", "RoutingRules"}
	object.get(wc, k, "__pf_absent") != "__pf_absent"
}
