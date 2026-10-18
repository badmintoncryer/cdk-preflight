package cdk_preflight

import rego.v1

# A target group belongs to the first service that forwards to it; a listener
# of another service is rejected ("TargetGroup tg-... has been associated with
# other services"). Only listener default actions are compared, and only when
# both listeners name services and the target group in the same template.
_pf_vpcllts_svc(l) := s if {
	s := resolve(l, "Properties.ServiceIdentifier")
	s in resources_of_type("AWS::VpcLattice::Service")
}

violation contains make_diag_full("pf-vpclattice-listener-tg-shared-across-services", "ERROR", name,
	sprintf("Properties.DefaultAction.Forward.TargetGroups.%d.TargetGroupIdentifier", [e[0]]),
	sprintf("Target group '%s' is also used by listener '%s' of service '%s'; CreateListener fails with \"has been associated with other services\"", [e[1], other, so]),
	"Create a separate target group for each service",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/http-listeners.html") if {
	some name in resources_of_type("AWS::VpcLattice::Listener")
	s := _pf_vpcllts_svc(name)
	some e in _pf_vpcl_fwd_tgs(name, "Properties.DefaultAction.Forward.TargetGroups")
	some other in resources_of_type("AWS::VpcLattice::Listener")
	other < name
	so := _pf_vpcllts_svc(other)
	so != s
	some e2 in _pf_vpcl_fwd_tgs(other, "Properties.DefaultAction.Forward.TargetGroups")
	e2[1] == e[1]
}
