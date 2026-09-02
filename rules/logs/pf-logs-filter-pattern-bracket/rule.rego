package cdk_preflight

import rego.v1

_pf_lgfpb_url := "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html"

_pf_lgfpb_msg(kind) := sprintf("The %s filter pattern starts with '[' but does not end with ']'; the service rejects it with \"If a filter pattern starts with '[' it must end with ']'\"", [kind])

_pf_lgfpb_fix := "Close the bracket — a space-delimited pattern is [field1, field2, ...]"

# The same parser runs for metric filters and subscription filters, and it
# runs before any destination validation (bench c01/c06). Only this
# start/end pairing is checked here; a full pattern parser is out of scope.
_pf_lgfpb_unbalanced(p) if {
	t := trim_space(p)
	startswith(t, "[")
	not endswith(t, "]")
}

violation contains make_diag_full("pf-logs-filter-pattern-bracket", "ERROR", name,
	"Properties.FilterPattern",
	_pf_lgfpb_msg("metric"),
	_pf_lgfpb_fix, _pf_lgfpb_url) if {
	some name in resources_of_type("AWS::Logs::MetricFilter")
	p := resolve(name, "Properties.FilterPattern")
	is_string(p)
	_pf_lgfpb_unbalanced(p)
}

violation contains make_diag_full("pf-logs-filter-pattern-bracket", "ERROR", name,
	"Properties.FilterPattern",
	_pf_lgfpb_msg("subscription"),
	_pf_lgfpb_fix, _pf_lgfpb_url) if {
	some name in resources_of_type("AWS::Logs::SubscriptionFilter")
	p := resolve(name, "Properties.FilterPattern")
	is_string(p)
	_pf_lgfpb_unbalanced(p)
}
