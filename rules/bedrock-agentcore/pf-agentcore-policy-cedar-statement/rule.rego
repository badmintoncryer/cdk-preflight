package cdk_preflight

import rego.v1

# Definition.Cedar.Statement is an opaque string (schema: length only). Two
# shapes measured to fail at CreatePolicy: text that is not a permit/forbid
# clause, a clause whose resource is unconstrained (bare `resource`), and a
# permit with an unconstrained principal and no when/unless condition
# ("Overly Permissive"). This is a cheap syntactic subset, not a Cedar parser.
_pf_cedar_url := "https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html"
_pf_cedar_path := "Properties.Definition.Cedar.Statement"
_pf_cedar_head := `(?s)^\s*(@[^\n]*\n\s*)*(permit|forbid)\s*\(`

_pf_cedar_stmt(name) := s if {
	s := resolve(name, _pf_cedar_path)
	is_string(s)
}

violation contains make_diag_full("pf-agentcore-policy-cedar-statement", "ERROR", name, _pf_cedar_path,
	"The Cedar statement does not start with permit( or forbid(; CreatePolicy fails with \"When parsing the policy statement, the following errors occurred\"",
	"Write a Cedar clause such as permit(principal, action == AgentCore::Action::\"<Target>___<tool>\", resource == AgentCore::Gateway::\"<gateway-arn>\");",
	_pf_cedar_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::Policy")
	s := _pf_cedar_stmt(name)
	not regex.match(_pf_cedar_head, s)
}

violation contains make_diag_full("pf-agentcore-policy-cedar-statement", "ERROR", name, _pf_cedar_path,
	"The Cedar statement leaves `resource` unconstrained; CreatePolicy fails with \"a wildcard resource was detected ... constrain the resource either to a specific AgentCore::Gateway resource or to the AgentCore::Gateway resource type\"",
	"Use resource == AgentCore::Gateway::\"<gateway-arn>\" or resource is AgentCore::Gateway in the clause head",
	_pf_cedar_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::Policy")
	s := _pf_cedar_stmt(name)
	regex.match(_pf_cedar_head, s)
	regex.match(`(?s)^\s*(@[^\n]*\n\s*)*(permit|forbid)\s*\([^)]*,\s*resource\s*\)`, s)
}

violation contains make_diag_full("pf-agentcore-policy-cedar-statement", "ERROR", name, _pf_cedar_path,
	"The permit clause has an unconstrained principal and no when/unless condition; CreatePolicy fails with \"Overly Permissive: Policy Engine will allow every request for the specified principal ... action ... and resource combination\"",
	"Add a when { ... } condition on context.input (or constrain the principal)",
	_pf_cedar_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::Policy")
	s := _pf_cedar_stmt(name)
	regex.match(`(?s)^\s*(@[^\n]*\n\s*)*permit\s*\(\s*principal\s*,`, s)
	not regex.match(`(?s)^\s*(@[^\n]*\n\s*)*(permit|forbid)\s*\([^)]*,\s*resource\s*\)`, s)
	not regex.match(`(?s)\)\s*(when|unless)\s*\{`, s)
}
