package cdk_preflight

import rego.v1

_pf_r53_apex_norm(n) := trim_suffix(lower(n), ".")

# The engine's E3023 catches an apex CNAME only when the record carries a
# literal HostedZoneName. CDK L2 always links records with
# HostedZoneId: {"Ref": <zone>}, which E3023 does not see (measured 2026-09-02,
# engine 1.7.0-beta). resolve() turns such a Ref into the target's logical ID,
# so when that ID names a HostedZone in the same template we can read its
# literal Name and do the apex comparison ourselves.
violation contains make_diag_full("pf-route53-apex-cname", "ERROR", name,
	"Properties.Type",
	sprintf("A CNAME record is not permitted at the zone apex ('%s'); the deployment fails with \"RRSet of type CNAME ... is not permitted at apex\"", [recName]),
	"Use an alias A/AAAA record for the apex (AliasTarget), or move the CNAME to a subdomain",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-choosing-alias-non-alias.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	resolve(name, "Properties.Type") == "CNAME"
	zref := resolve(name, "Properties.HostedZoneId")
	is_string(zref)
	zref in resources_of_type("AWS::Route53::HostedZone")
	zoneName := resolve(zref, "Properties.Name")
	is_string(zoneName)
	recName := resolve(name, "Properties.Name")
	is_string(recName)
	_pf_r53_apex_norm(recName) == _pf_r53_apex_norm(zoneName)
}
