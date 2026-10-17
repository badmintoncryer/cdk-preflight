package cdk_preflight

import rego.v1

# TCP target groups serve TLS_PASSTHROUGH listeners only; CreateListener
# rejects them behind an HTTP or HTTPS listener ("Incompatible target group
# protocol TCP with listener protocol HTTPS"). Checked for target groups
# defined in the same template.
violation contains make_diag_full("pf-vpclattice-listener-http-tg-tcp", "ERROR", name,
	sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [e[0]]),
	sprintf("Target group '%s' uses TCP; CreateListener fails with \"Incompatible target group protocol TCP with listener protocol %s\"", [e[1], p]),
	"Forward to an HTTP or HTTPS target group, or make the listener TLS_PASSTHROUGH",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	p := resolve(name, "Properties.Protocol")
	p in {"HTTP", "HTTPS"}
	some e in _pf_vpcl_fwd_tgs(name, "Properties.DefaultAction.Forward.TargetGroups")
	resolve(e[1], "Properties.Config.Protocol") == "TCP"
}
