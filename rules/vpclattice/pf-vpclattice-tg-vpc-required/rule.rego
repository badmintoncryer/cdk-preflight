package cdk_preflight

import rego.v1

# Config and Config.VpcIdentifier are optional in the schema because a LAMBDA
# target group has neither. Every other type is rejected without them
# ("Config fields port|protocol|vpcIdentifier must not be null for INSTANCE
# Target Group", or "INSTANCE Target Group must include a config" when Config is
# absent). Only VpcIdentifier is checked.
violation contains make_diag_full("pf-vpclattice-tg-vpc-required", "ERROR", name,
	"Properties.Config.VpcIdentifier",
	sprintf("A %s target group needs Config.VpcIdentifier; CreateTargetGroup fails with \"Config fields port|protocol|vpcIdentifier must not be null for %s Target Group\"", [t, t]),
	"Set Config.VpcIdentifier (and Port and Protocol) to the VPC of the targets",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_TargetGroupConfig.html") if {
	some name in _pf_vpcl_tgs
	t := _pf_vpcl_tgtype(name)
	t in {"INSTANCE", "IP", "ALB"}
	not _pf_vpcl_has(name, "Properties.Config.VpcIdentifier")
}
