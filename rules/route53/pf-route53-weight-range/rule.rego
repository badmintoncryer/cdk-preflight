package cdk_preflight

import rego.v1

# Only the measured bound is enforced: the service rejected 300 with "Member
# must have value less than or equal to 255". Negative weights are untested,
# so they are deliberately not flagged.
violation contains make_diag_full("pf-route53-weight-range", "ERROR", name,
	"Properties.Weight",
	sprintf("Weight must be at most 255, got %v", [n]),
	"Set Weight to a value in [0, 255]; weights are relative, so scale the group down proportionally",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	w := resolve(name, "Properties.Weight")
	n := to_number(w)
	n > 255
}
