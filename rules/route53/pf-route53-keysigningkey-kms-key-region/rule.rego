package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-keysigningkey-kms-key-region", "ERROR", name,
	"Properties.KeyManagementServiceArn",
	sprintf("the signing key is in %s; Route 53 DNSSEC only reads customer managed keys from us-east-1", [rg]),
	"Create the signing key in us-east-1",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::KeySigningKey")
	a := resolve(name, "Properties.KeyManagementServiceArn")
	is_string(a)
	startswith(a, "arn:")
	parts := split(a, ":")
	count(parts) > 4
	rg := parts[3]
	rg != ""
	rg != "us-east-1"
}
