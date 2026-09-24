package cdk_preflight

import rego.v1

# A PortRange is inclusive, so FromPort above ToPort names no port at all and
# CreateListener answers InvalidPortRangeException. The schema bounds each end to
# 0-65535 on its own and never compares the two.
violation contains make_diag_full("pf-ga-listener-port-range-order", "ERROR", name,
	sprintf("Properties.PortRanges.%d", [r.index]),
	sprintf("The listener port range runs from %v down to %v; FromPort must not be greater than ToPort", [f, t]),
	"Swap the two ends so FromPort <= ToPort (a single port is FromPort == ToPort)",
	"https://docs.aws.amazon.com/global-accelerator/latest/api/API_CreateListener.html") if {
	some name in _pf_galib_listeners
	some r in flatten_list(name, "Properties.PortRanges")
	f := _pf_galib_int(_pf_galib_oget(r.value, "FromPort"))
	t := _pf_galib_int(_pf_galib_oget(r.value, "ToPort"))
	f > t
}
