package cdk_preflight

import rego.v1

# The registry schema has Min 0 / Max 2048 and no pattern; the API's pattern
# admits only letters, separators, numbers and punctuation, so every symbol
# (> < = + | ~ ^ $ and every emoji) is rejected. The length end is the schema's
# and is deliberately left out of the expression here (principle 1) — and the
# API's {0,2048} does not compile in this engine anyway: what blows up is the
# size of the compiled pattern (class width × repeat count), not a repeat-count
# cap. On a rejected pattern regex.match is undefined, not false, so this rule's
# not regex.match would fire on every Description. regex.is_valid(p) == false is
# the one-line self-check.
violation contains make_diag_full("pf-grafana-ws-description-charset", "ERROR", name,
	"Properties.Description",
	sprintf("Description \"%v\" holds a character outside the letter, separator, number and punctuation categories; CreateWorkspace fails with \"The workspaceDescription should satisfy the pattern ^[\\p{L}\\p{Z}\\p{N}\\p{P}]{0,2048}$.\"", [d]),
	"Spell out symbols such as > < = + | ~ ^ $ and drop emoji from the description",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-grafana-workspace.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	d := resolve(name, "Properties.Description")
	is_string(d)
	not regex.match(`^[\p{L}\p{Z}\p{N}\p{P}]*$`, d)
}
