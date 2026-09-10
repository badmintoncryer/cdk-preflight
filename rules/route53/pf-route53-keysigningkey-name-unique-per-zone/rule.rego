package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-name-unique-per-zone", "ERROR", name,
	"Properties.Name",
	sprintf("key signing keys %s and %s carry the same Name in the same hosted zone", [name, other]),
	"Give each key signing key its own name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	some other in resources_of_type("AWS::Route53::KeySigningKey")
	name < other
	_pf_r53z_zone_of(name) == _pf_r53z_zone_of(other)
	n := _pf_r53z_str(_pf_r53z_props(name), "Name")
	n == _pf_r53z_str(_pf_r53z_props(other), "Name")
}
