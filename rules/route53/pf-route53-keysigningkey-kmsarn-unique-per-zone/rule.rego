package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kmsarn-unique-per-zone", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("key signing keys %s and %s use the same KMS key in the same hosted zone", [name, other]),
	"Create a second KMS key for the second key signing key",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	some other in resources_of_type("AWS::Route53::KeySigningKey")
	name < other
	_pf_r53z_zone_of(name) == _pf_r53z_zone_of(other)
	resolve(name, "Properties.KeyManagementServiceArn") == resolve(other, "Properties.KeyManagementServiceArn")
}
