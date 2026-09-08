package cdk_preflight

import rego.v1

# Shared helpers for the CloudWatch rules.

# True absence needs the preprocessed document (see AGENTS.md); resolve() is
# undefined for a missing key, so "resolve(...) != x" never fires on one.
_pf_cwlib_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

# The statistic grammar CloudWatch accepts wherever a statistic is a string:
# MetricStat.Stat, a dashboard widget's "stat", PutAnomalyDetector's Stat and
# a metric stream's AdditionalStatistics. Percentiles stop at 100, which is
# why the numeric part is spelled out instead of [0-9.]+ (p101 is rejected by
# the service with "Unsupported statistic p101").
# ponytail: the trimmed-mean interval forms (TM(10%:90%)) are matched loosely;
# a malformed interval passes the rule and is caught by the service.
_pf_cwlib_stat_re := `^(SampleCount|Average|Sum|Minimum|Maximum|IQM|[pP](100|[0-9]{1,2}(\.[0-9]{1,2})?)|(TM|TC|TS|WM|tm|tc|ts|wm)((100|[0-9]{1,2}(\.[0-9]{1,2})?)%?|\([0-9.%:]*\))|PR\([0-9.:]*\))$`

_pf_cwlib_stat_ok(s) if regex.match(_pf_cwlib_stat_re, s)

# DashboardBody is an opaque JSON string; every dashboard rule reads it here.
_pf_cwlib_widgets(name) := ws if {
	body := resolve(name, "Properties.DashboardBody")
	is_string(body)
	json.is_valid(body)
	obj := json.unmarshal(body)
	is_object(obj)
	ws := object.get(obj, "widgets", [])
	is_array(ws)
}

_pf_cwlib_wprops(w) := p if {
	is_object(w)
	p := object.get(w, "properties", null)
	is_object(p)
}

_pf_cwlib_wtype(w, t) if {
	is_object(w)
	object.get(w, "type", null) == t
}

# InsightRule RuleBody is the other opaque JSON DSL on this service.
_pf_cwlib_rulebody(name) := obj if {
	b := resolve(name, "Properties.RuleBody")
	is_string(b)
	json.is_valid(b)
	obj := json.unmarshal(b)
	is_object(obj)
}

# The three alarm action lists, shared by the action rules.
_pf_cwlib_action_keys := {"AlarmActions", "OKActions", "InsufficientDataActions"}

# Metric queries of one kind (MetricStat / Expression) on an alarm.
_pf_cwlib_queries(name, key) := qs if {
	qs := [q |
		some item in flatten_list(name, "Properties.Metrics")
		q := item.value
		is_object(q)
		object.get(q, key, null) != null
	]
}

# A literal ARN split into its six-plus segments. Refs and GetAtts resolve to a
# logical id, which has no "arn:" prefix, so they skip.
_pf_cwlib_arn(v) := parts if {
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
}
