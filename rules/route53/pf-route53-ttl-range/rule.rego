package cdk_preflight

import rego.v1

# Only the measured bound is enforced: the service rejected 9999999999 with
# "Member must have value less than or equal to 2147483647". Negative TTLs are
# untested, so they are deliberately not flagged.
violation contains make_diag_full("pf-route53-ttl-range", "ERROR", name,
	"Properties.TTL",
	sprintf("TTL must be at most 2147483647 seconds, got %v", [n]),
	"Set TTL to a 32-bit value; anything above a day rarely helps caching anyway",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	t := resolve(name, "Properties.TTL")
	n := to_number(t)
	n > 2147483647
}
