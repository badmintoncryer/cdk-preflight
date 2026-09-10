package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-status-enum", "ERROR", name,
	"Properties.Status",
	sprintf("key signing key status %s is neither ACTIVE nor INACTIVE", [s]),
	"Use ACTIVE or INACTIVE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	s := _pf_r53z_str(_pf_r53z_props(name), "Status")
	not s in {"ACTIVE", "INACTIVE"}
}
