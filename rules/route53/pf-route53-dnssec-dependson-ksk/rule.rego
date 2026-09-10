package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-dnssec-dependson-ksk", "ERROR", name,
	"DependsOn",
	sprintf("AWS::Route53::DNSSEC does not reference key signing key %s, so CloudFormation may create it first and fail with DNSSECNotFound", [k]),
	"Add DependsOn for the key signing key",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::DNSSEC")
	z := _pf_r53z_zone_of(name)
	deps := object.get(input.resources[name], "dependsOn", [])
	some k in _pf_r53z_ksks_of(z)
	not k in deps
}
