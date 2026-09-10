package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kms-key-policy-principal", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("the key policy of %s has no Allow statement for dnssec-route53.amazonaws.com", [k]),
	"Add a statement allowing the dnssec-route53.amazonaws.com service principal to use the key",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	k := _pf_r53z_key_of(name)
	not _pf_r53z_key_grants(k)
}
