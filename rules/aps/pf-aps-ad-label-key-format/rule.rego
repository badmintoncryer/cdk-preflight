package cdk_preflight

import rego.v1

_pf_aps_adlk_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-aps-anomalydetector-label.html"

_pf_aps_adlk_fix := "Use a Prometheus label name: a letter or underscore first, then letters, digits and underscores, and not the reserved __ prefix"

# The CloudFormation schema carries no pattern for Labels[].Key. The service
# full-matches (?!__)[a-zA-Z_][a-zA-Z0-9_]*, which RE2 cannot express -- there is
# no lookahead -- so the charset and the reserved prefix are two checks. Both
# emit the same diagnostic, so a key that breaks both is reported once.
violation contains make_diag_full("pf-aps-ad-label-key-format", "ERROR", name,
	"Properties.Labels",
	sprintf("label key \"%v\" is not a full match for (?!__)[a-zA-Z_][a-zA-Z0-9_]*; CreateAnomalyDetector fails with \"Invalid labels: Map keys must satisfy constraint: [... Member must satisfy regular expression pattern: (?!__)[a-zA-Z_][a-zA-Z0-9_]*]\"", [k]),
	_pf_aps_adlk_fix, _pf_aps_adlk_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	some label in _pf_aps_ad_labels(name)
	k := object.get(label, "Key", null)
	is_string(k)
	not regex.match(`^[a-zA-Z_][a-zA-Z0-9_]*$`, k)
}

violation contains make_diag_full("pf-aps-ad-label-key-format", "ERROR", name,
	"Properties.Labels",
	sprintf("label key \"%v\" is not a full match for (?!__)[a-zA-Z_][a-zA-Z0-9_]*; CreateAnomalyDetector fails with \"Invalid labels: Map keys must satisfy constraint: [... Member must satisfy regular expression pattern: (?!__)[a-zA-Z_][a-zA-Z0-9_]*]\"", [k]),
	_pf_aps_adlk_fix, _pf_aps_adlk_url) if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	some label in _pf_aps_ad_labels(name)
	k := object.get(label, "Key", null)
	is_string(k)
	startswith(k, "__")
}
