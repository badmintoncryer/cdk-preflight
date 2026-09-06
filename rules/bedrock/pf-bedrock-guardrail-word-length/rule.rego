package cdk_preflight

import rego.v1

# The API documents a 100-character maximum on Text; the schema only has
# minLength 1 (measured 2026-09-06: 101 characters fail).
violation contains make_diag_full("pf-bedrock-guardrail-word-length", "ERROR", name,
	sprintf("Properties.WordPolicyConfig.WordsConfig[%d].Text", [i]),
	sprintf("Custom word is %d characters (maximum 100); CreateGuardrail fails with \"The custom word length in this Word policy exceeds quota limit\"", [n]),
	"Shorten the word or phrase to 100 characters",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_GuardrailWordConfig.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	xs := object.get(object.get(p, "WordPolicyConfig", {}), "WordsConfig", [])
	some i, x in xs
	is_object(x)
	t := x.Text
	is_string(t)
	n := count(t)
	n > 100
}
