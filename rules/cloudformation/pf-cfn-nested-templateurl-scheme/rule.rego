package cdk_preflight

import rego.v1

# TemplateURL is typed as a plain string, so an s3:// URI - the form every
# other AWS tool takes - passes synth and schema validation untouched.
_pf_cfnnesturl_bad contains [name, url] if {
	some name in resources_of_type("AWS::CloudFormation::Stack")
	url := resolve(name, "Properties.TemplateURL")
	is_string(url)
	not startswith(url, "https://")
}

violation contains make_diag_full("pf-cfn-nested-templateurl-scheme", "ERROR", name,
	"Properties.TemplateURL",
	sprintf("TemplateURL '%s' is not an https:// URL; CloudFormation fails the nested stack with \"The location for an Amazon S3 bucket must start with https://\"", [url]),
	"Use the https:// form of the S3 object URL, not an s3:// URI",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-stack.html") if {
	some [name, url] in _pf_cfnnesturl_bad
}
