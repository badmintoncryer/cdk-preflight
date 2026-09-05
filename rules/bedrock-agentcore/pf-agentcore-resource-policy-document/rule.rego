package cdk_preflight

import rego.v1

# Policy is an opaque string in the schema (the existing pf-iam-policy-* rules
# only look at AWS::IAM::* resources). PutResourcePolicy validates it: valid
# JSON, at least one statement, Principal on every statement, actions in the
# bedrock-agentcore namespace, and a single Resource ARN (no "*"). Policies
# built with Fn::Sub / Fn::Join over resource references do not resolve and
# are skipped.
_pf_acrp_url := "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_PutResourcePolicy.html"

_pf_acrp_doc(name) := doc if {
	s := resolve(name, "Properties.Policy")
	is_string(s)
	doc := json.unmarshal(s)
	is_object(doc)
}

_pf_acrp_stmts(name) := [x | some x in _pf_acrp_list(object.get(_pf_acrp_doc(name), "Statement", null)); is_object(x)]

_pf_acrp_list(v) := v if is_array(v)

_pf_acrp_list(v) := [v] if is_object(v)

_pf_acrp_list(v) := [v] if is_string(v)

_pf_acrp_list(v) := [] if v == null

violation contains make_diag_full("pf-agentcore-resource-policy-document", "ERROR", name, "Properties.Policy",
	"Policy is not a JSON document; PutResourcePolicy fails with \"This policy contains invalid Json\"",
	"Pass a JSON policy document (as a string, or JSON.stringify of an object)", _pf_acrp_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ResourcePolicy")
	s := resolve(name, "Properties.Policy")
	is_string(s)
	not json.is_valid(s)
}

violation contains make_diag_full("pf-agentcore-resource-policy-document", "ERROR", name, "Properties.Policy",
	"Policy has no Statement; PutResourcePolicy fails with \"Policy has no statements\"",
	"Add a Statement list with at least one entry", _pf_acrp_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ResourcePolicy")
	_pf_acrp_doc(name)
	count(_pf_acrp_stmts(name)) == 0
}

violation contains make_diag_full("pf-agentcore-resource-policy-document", "ERROR", name,
	sprintf("Properties.Policy.Statement[%d].Principal", [i]),
	"A statement has no Principal; PutResourcePolicy fails with \"Missing required field Principal\"",
	"Add Principal (e.g. {\"AWS\": \"arn:aws:iam::<account>:root\"}) to every statement", _pf_acrp_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ResourcePolicy")
	some i, st in _pf_acrp_stmts(name)
	object.get(st, "Principal", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-agentcore-resource-policy-document", "ERROR", name,
	sprintf("Properties.Policy.Statement[%d].Action", [i]),
	sprintf("Action '%s' is outside the bedrock-agentcore namespace; PutResourcePolicy fails with \"Policy has invalid action\"", [a]),
	"Use bedrock-agentcore:* actions only (e.g. bedrock-agentcore:InvokeGateway)", _pf_acrp_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ResourcePolicy")
	some i, st in _pf_acrp_stmts(name)
	some a in _pf_acrp_list(object.get(st, "Action", null))
	is_string(a)
	not startswith(a, "bedrock-agentcore:")
}

violation contains make_diag_full("pf-agentcore-resource-policy-document", "ERROR", name,
	sprintf("Properties.Policy.Statement[%d].Resource", [i]),
	"A statement must name exactly one Resource ARN equal to ResourceArn (\"*\" or a list is rejected); PutResourcePolicy fails with \"Policy statement block must contain exactly one resource ARN that matches the provided resource ARN\"",
	"Set Resource to the same ARN as ResourceArn (use Fn::Sub / Fn::GetAtt for a resource in the template)", _pf_acrp_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ResourcePolicy")
	some i, st in _pf_acrp_stmts(name)
	res := _pf_acrp_list(object.get(st, "Resource", null))
	not _pf_acrp_single_arn(res)
}

_pf_acrp_single_arn(res) if {
	count(res) == 1
	is_string(res[0])
	startswith(res[0], "arn:")
}
