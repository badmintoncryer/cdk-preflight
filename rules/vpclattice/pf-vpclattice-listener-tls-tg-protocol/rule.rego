package cdk_preflight

import rego.v1

# A TLS_PASSTHROUGH listener hands the TCP stream on unchanged, so CreateListener
# accepts only TCP target groups ("Incompatible target group protocol HTTP with
# listener protocol TLS_PASSTHROUGH"; a LAMBDA target group: "Incompatible
# target group type LAMBDA with listener protocol TLS_PASSTHROUGH"). Checked
# for target groups defined in the same template.
_pf_vpcllttp_bad(tg) := sprintf("protocol %s", [p]) if {
	_pf_vpcl_tgtype(tg) != "LAMBDA"
	p := resolve(tg, "Properties.Config.Protocol")
	is_string(p)
	p != "TCP"
}

_pf_vpcllttp_bad(tg) := "type LAMBDA" if _pf_vpcl_tgtype(tg) == "LAMBDA"

violation contains make_diag_full("pf-vpclattice-listener-tls-tg-protocol", "ERROR", name,
	sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [e[0]]),
	sprintf("Target group '%s' has %s; CreateListener fails with \"Incompatible target group ... with listener protocol TLS_PASSTHROUGH\"", [e[1], why]),
	"Forward a TLS_PASSTHROUGH listener to a TCP target group (Config.Protocol TCP)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/tls-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	resolve(name, "Properties.Protocol") == "TLS_PASSTHROUGH"
	some e in _pf_vpcl_fwd_tgs(name, "Properties.DefaultAction.Forward.TargetGroups")
	why := _pf_vpcllttp_bad(e[1])
}
