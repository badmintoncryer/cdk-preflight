package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kms-key-enabled", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("the key signing key points at %s, which is created disabled; Route 53 cannot sign with it", [k]),
	"Enable the KMS key",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-keysigningkey.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	k := _pf_r53z_key_of(name)
	object.get(_pf_r53z_props(k), "Enabled", true) == false
}
