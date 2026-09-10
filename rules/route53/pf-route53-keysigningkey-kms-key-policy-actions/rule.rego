package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kms-key-policy-actions", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("the key policy of %s does not allow dnssec-route53.amazonaws.com to %v", [k, _pf_r53z_missing_actions(k)]),
	"Allow kms:DescribeKey, kms:GetPublicKey and kms:Sign for dnssec-route53.amazonaws.com",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	k := _pf_r53z_key_of(name)
	_pf_r53z_key_grants(k)
	count(_pf_r53z_missing_actions(k)) > 0
}
