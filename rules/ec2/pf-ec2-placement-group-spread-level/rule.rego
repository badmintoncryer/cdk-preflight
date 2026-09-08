package cdk_preflight

import rego.v1

_pf_ec2pgs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-placementgroup.html"

# Measured, not transcribed: the API message names *two* strategies, so a
# partition group may carry SpreadLevel even though the survey said spread only.
violation contains make_diag_full("pf-ec2-placement-group-spread-level", "ERROR", name,
	"Properties.SpreadLevel",
	sprintf("SpreadLevel is set with the '%s' strategy (\"spread-level is only available with the 'spread' or 'partition' strategy.\")", [s]),
	"Set Strategy to spread or partition, or drop SpreadLevel",
	_pf_ec2pgs_url) if {
	some name in resources_of_type("AWS::EC2::PlacementGroup")
	not _pf_ec2lib_absent(name, "SpreadLevel")
	s := resolve(name, "Properties.Strategy")
	is_string(s)
	not s in {"spread", "partition"}
}
