package cdk_preflight

import rego.v1

# The API documents a 500-character maximum on Pattern; the schema only has
# minLength 1 (measured 2026-09-06: 501 characters fail).
violation contains make_diag_full("pf-bedrock-guardrail-regex-pattern-length", "ERROR", name,
	sprintf("Properties.SensitiveInformationPolicyConfig.RegexesConfig[%d].Pattern", [i]),
	sprintf("Regex pattern is %d characters (maximum 500); CreateGuardrail fails with \"Regex length in sensitive information policy exceeds quota limit\"", [n]),
	"Shorten the pattern to 500 characters or split it into several regex filters",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailRegexConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "SensitiveInformationPolicyConfig", {}), "RegexesConfig", [])
	some i, x in xs
	is_object(x)
	pat := x.Pattern
	is_string(pat)
	n := count(pat)
	n > 500
}
