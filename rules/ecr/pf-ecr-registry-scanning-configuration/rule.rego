package cdk_preflight

import rego.v1

_pf_ecrscan_url := "https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_PutRegistryScanningConfiguration.html"

_pf_ecrscan_fix := "Use SCAN_ON_PUSH with ScanType BASIC, or switch ScanType to ENHANCED for CONTINUOUS_SCAN; give each rule its own frequency"

_pf_ecrscan_rules(name) := rules if {
	rules := resolve(name, "Properties.Rules")
	is_array(rules)
}

violation contains make_diag_full("pf-ecr-registry-scanning-configuration", "ERROR", name,
	sprintf("Properties.Rules[%d].ScanFrequency", [i]),
	"ScanType is BASIC but the rule asks for CONTINUOUS_SCAN; PutRegistryScanningConfiguration fails with \"Invalid scan frequency for scanType BASIC: CONTINUOUS_SCAN\"",
	_pf_ecrscan_fix, _pf_ecrscan_url) if {
	some name in resources_of_type("AWS::ECR::RegistryScanningConfiguration")
	resolve(name, "Properties.ScanType") == "BASIC"
	some i, rule in _pf_ecrscan_rules(name)
	object.get(rule, "ScanFrequency", null) == "CONTINUOUS_SCAN"
}

violation contains make_diag_full("pf-ecr-registry-scanning-configuration", "ERROR", name,
	sprintf("Properties.Rules[%d].ScanFrequency", [i]),
	sprintf("two rules use the scan frequency %s; PutRegistryScanningConfiguration fails with \"Invalid input. Contains duplicate scan frequencies: [%s]\"", [f, f]),
	_pf_ecrscan_fix, _pf_ecrscan_url) if {
	some name in resources_of_type("AWS::ECR::RegistryScanningConfiguration")
	rules := _pf_ecrscan_rules(name)
	some i, rule in rules
	f := object.get(rule, "ScanFrequency", null)
	is_string(f)
	some j, other in rules
	j != i
	object.get(other, "ScanFrequency", null) == f
}
