package cdk_preflight

import rego.v1

_pf_cfgrrv_err := "the remediation create fails: RESOURCE_ID is the only accepted resource value"

violation contains make_diag_full("pf-config-remediation-resource-value-allowed", "ERROR", name,
	sprintf("Properties.Parameters.%s.ResourceValue.Value", [k]),
	sprintf("remediation parameter %s sets ResourceValue.Value to %v; %s", [k, val, _pf_cfgrrv_err]),
	"Use RESOURCE_ID - it is the only resource attribute AWS Config passes to the remediation",
	"https://docs.aws.amazon.com/config/latest/APIReference/API_ResourceValue.html") if {
	some name in resources_of_type("AWS::Config::RemediationConfiguration")
	some k, v in _pf_cfglib_parameters(name)
	val := object.get(_pf_cfglib_obj(v, "ResourceValue"), "Value", null)
	is_string(val)
	val != "RESOURCE_ID"
}
