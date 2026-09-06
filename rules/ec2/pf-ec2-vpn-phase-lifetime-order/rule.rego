package cdk_preflight

import rego.v1

# Both values can sit inside their own documented ranges (F3034 covers those)
# and still be rejected, because phase 2 must expire before phase 1.
violation contains make_diag_full("pf-ec2-vpn-phase-lifetime-order", "ERROR", name,
	sprintf("Properties.VpnTunnelOptionsSpecifications.%d.Phase2LifetimeSeconds", [item.index]),
	sprintf("Phase2LifetimeSeconds (%v) must be less than Phase1LifetimeSeconds (%v)", [p2, p1]),
	"Lower Phase2LifetimeSeconds below Phase1LifetimeSeconds",
	"https://docs.aws.amazon.com/vpn/latest/s2svpn/VPNTunnels.html") if {
	some name in resources_of_type("AWS::EC2::VPNConnection")
	some item in flatten_list(name, "Properties.VpnTunnelOptionsSpecifications")
	p1 := to_number(object.get(item.value, "Phase1LifetimeSeconds", null))
	p2 := to_number(object.get(item.value, "Phase2LifetimeSeconds", null))
	p2 > p1
}
