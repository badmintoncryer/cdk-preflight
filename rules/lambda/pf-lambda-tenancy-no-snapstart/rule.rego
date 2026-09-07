package cdk_preflight

import rego.v1

_pf_ltns_fix := "Drop SnapStart, or drop TenancyConfig"

_pf_ltns_url := "https://docs.aws.amazon.com/lambda/latest/dg/tenant-isolation.html"

violation contains make_diag_full("pf-lambda-tenancy-no-snapstart", "ERROR", fname,
	"Properties.SnapStart",
	"SnapStart on a tenant-isolated function; the snapshot is shared across invocations and cannot be reused per tenant",
	_pf_ltns_fix, _pf_ltns_url) if {
	some fname in _pf_lam_fn
	_pf_lam_has(fname, "TenancyConfig")
	object.get(_pf_lam_obj(_pf_lam_props(fname), "SnapStart"), "ApplyOn", "None") != "None"
}
