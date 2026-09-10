package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53-dnssec-requires-active-ksk", "ERROR", name,
	"Properties.HostedZoneId",
	sprintf("every key signing key on hosted zone %s is INACTIVE; enabling DNSSEC fails with KeySigningKeyWithActiveStatusNotFound", [z]),
	"Set one key signing key to ACTIVE",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html") if {
	some name in resources_of_type("AWS::Route53::DNSSEC")
	z := _pf_r53z_zone_of(name)
	ksks := _pf_r53z_ksks_of(z)
	count(ksks) > 0
	count([k | some k in ksks; object.get(_pf_r53z_props(k), "Status", "") == "ACTIVE"]) == 0
}
