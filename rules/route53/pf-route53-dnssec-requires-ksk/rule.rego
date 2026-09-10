package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-dnssec-requires-ksk", "ERROR", name,
	"Properties.HostedZoneId",
	sprintf("hosted zone %s is created in this template with no key signing key; enabling DNSSEC fails with DNSSECNotFound", [z]),
	"Add an AWS::Route53::KeySigningKey for the zone and DependsOn it",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::DNSSEC")
	z := _pf_r53z_zone_of(name)
	count(_pf_r53z_ksks_of(z)) == 0
}
