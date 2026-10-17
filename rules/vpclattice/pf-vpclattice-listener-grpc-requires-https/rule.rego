package cdk_preflight

import rego.v1

# Config.ProtocolVersion GRPC needs HTTP/2 end to end; CreateListener rejects
# such a target group behind an HTTP listener ("Target group tg-... with
# protocol version GRPC can only be used in an HTTPS listener"). Checked for
# target groups defined in the same template.
violation contains make_diag_full("pf-vpclattice-listener-grpc-requires-https", "ERROR", name,
	sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [e[0]]),
	sprintf("Target group '%s' uses ProtocolVersion GRPC; CreateListener fails with \"with protocol version GRPC can only be used in an HTTPS listener\"", [e[1]]),
	"Use an HTTPS listener, or a target group with ProtocolVersion HTTP1",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-groups.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	resolve(name, "Properties.Protocol") == "HTTP"
	some e in _pf_vpcl_fwd_tgs(name, "Properties.DefaultAction.Forward.TargetGroups")
	resolve(e[1], "Properties.Config.ProtocolVersion") == "GRPC"
}
