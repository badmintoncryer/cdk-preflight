package cdk_preflight

import rego.v1

_pf_llcr_fix := "List runtime identifiers Lambda knows, such as python3.12 or nodejs22.x"

_pf_llcr_url := "https://docs.aws.amazon.com/lambda/latest/api/API_PublishLayerVersion.html"

_pf_llcr_known := {
	"nodejs16.x", "nodejs18.x", "nodejs20.x", "nodejs22.x", "nodejs24.x", "nodejs26.x",
	"python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14", "python3.15",
	"java8.al2", "java8.al2023", "java11", "java11.al2023", "java17", "java17.al2023", "java21", "java25",
	"dotnet6", "dotnet8", "dotnet10",
	"ruby3.2", "ruby3.3", "ruby3.4", "ruby4.0",
	"provided.al2", "provided.al2023",
}

violation contains make_diag_full("pf-lambda-layer-compatible-runtimes-enum", "ERROR", name,
	"Properties.CompatibleRuntimes",
	sprintf("runtime '%v' is not a Lambda runtime identifier", [v]),
	_pf_llcr_fix, _pf_llcr_url) if {
	some name in _pf_lam_layer
	vs := _pf_lam_list(_pf_lam_get(name, "CompatibleRuntimes"))
	some v in vs
	is_string(v)
	not v in _pf_llcr_known
}
