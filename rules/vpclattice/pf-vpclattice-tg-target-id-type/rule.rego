package cdk_preflight

import rego.v1

# Target.Id is a free string in the schema; its form depends on the target
# group type. For Type INSTANCE, RegisterTargets rejects anything but an
# instance ID ("Provided instance id: 10.0.0.10 is invalid. Instance id must
# match: (i-[a-f0-9]+)"). Only INSTANCE target groups are checked.
violation contains make_diag_full("pf-vpclattice-tg-target-id-type", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("Target '%s' is not an EC2 instance ID; RegisterTargets fails with \"Instance id must match: (i-[a-f0-9]+)\"", [id]),
	"Register EC2 instance IDs (i-...), or use Type IP for IP addresses",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_Target.html") if {
	some name in _pf_vpcl_tgs_of("INSTANCE")
	some t in flatten_list(name, "Properties.Targets")
	id := _pf_vpcl_target_id(t)
	not regex.match(`^i-[a-f0-9]+$`, id)
}
