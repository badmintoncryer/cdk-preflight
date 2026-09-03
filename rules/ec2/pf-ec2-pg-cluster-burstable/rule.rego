package cdk_preflight

import rego.v1

# Cross-resource: only fires when the referenced placement group is in
# the template with Strategy cluster. A literal (pre-existing) group
# name carries no strategy information and stays silent.
_pf_ec2pgb_burstable(fam) if fam in {"t2", "t3", "t3a", "t4g"}

violation contains make_diag_full("pf-ec2-pg-cluster-burstable", "ERROR", name,
	"Properties.InstanceType",
	sprintf("Cluster placement groups are not supported by the '%s' instance type; the launch fails at deploy", [it]),
	"Use a non-burstable type, or a spread/partition placement group",
	"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/placement-groups.html") if {
	some name in resources_of_type("AWS::EC2::Instance")
	it := resolve(name, "Properties.InstanceType")
	is_string(it)
	_pf_ec2pgb_burstable(split(it, ".")[0])
	pg := resolve(name, "Properties.PlacementGroupName")
	pg in resources_of_type("AWS::EC2::PlacementGroup")
	resolve(pg, "Properties.Strategy") == "cluster"
}
