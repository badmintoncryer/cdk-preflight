package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileresourceassociation-querylogging-max", "ERROR", name,
	"Properties.ResourceArn",
	sprintf("this template associates %d Resolver query logging configs with the same Profile; only one is allowed", [n]),
	"Associate at most one query logging config per Profile",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
	p := _pf_r53r_props(name)
	_pf_r53r_pra_kind(p) == "resolver-query-log-config"
	k := _pf_r53r_key(p, "ProfileId")
	n := count([1 |
		some o in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
		q := _pf_r53r_props(o)
		_pf_r53r_pra_kind(q) == "resolver-query-log-config"
		_pf_r53r_key(q, "ProfileId") == k
	])
	n > 1
}
