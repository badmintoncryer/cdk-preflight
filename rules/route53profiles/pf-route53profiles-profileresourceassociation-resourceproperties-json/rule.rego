package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileresourceassociation-resourceproperties-json", "ERROR", name,
	"Properties.ResourceProperties",
	sprintf("ResourceProperties is '%s', which is not a JSON object", [s]),
	"Pass a JSON object string such as {\"priority\": 101}",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53profiles-profileresourceassociation.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
	s := _pf_r53r_str(_pf_r53r_props(name), "ResourceProperties")
	not regex.match(`^\s*\{`, s)
}
