package cdk_preflight

import rego.v1

# The registry schema has Min 0 / Max 2048 and no pattern; the API's pattern
# admits only letters, separators, numbers and punctuation, so every symbol
# (> < = + | ~ ^ $ and every emoji) is rejected. The length end is the schema's
# and is deliberately left out of the expression here (principle 1) — and Go's
# regexp rejects a repeat count above 1000 outright, which would silence the rule.
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
