package cdk_preflight

import rego.v1

_pf_lcprt_fix := "Use Java 21+, Python 3.13+, Node.js 22+, .NET 8+ or provided.al2023"

_pf_lcprt_url := "https://docs.aws.amazon.com/lambda/latest/dg/lambda-managed-instances-runtimes.html"

_pf_lcprt_ok := {"java21", "java25", "python3.13", "python3.14", "nodejs22.x", "nodejs24.x", "dotnet8", "dotnet10", "provided.al2023"}

violation contains make_diag_full("pf-lambda-capacity-provider-runtime", "ERROR", name,
	"Properties.Runtime",
	sprintf("runtime '%v' with a capacity provider; Lambda Managed Instances run Java 21+, Python 3.13+, Node.js 22+, .NET 8+ and Rust on provided.al2023 only", [rt]),
	_pf_lcprt_fix, _pf_lcprt_url) if {
	some name in _pf_lam_fn
	cpc := _pf_lam_obj(_pf_lam_props(name), "CapacityProviderConfig")
	lmi := _pf_lam_obj(cpc, "LambdaManagedInstancesCapacityProviderConfig")
	lmi == lmi
	rt := _pf_lam_str(_pf_lam_props(name), "Runtime")
	_pf_lam_lit(rt)
	not rt in _pf_lcprt_ok
}
