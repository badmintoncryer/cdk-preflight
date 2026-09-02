package cdk_preflight

import rego.v1

# S3 keeps one notification configuration per bucket and rejects it when two
# entries (across queue/topic/lambda alike) could match the same object event:
# overlapping event types AND overlapping prefixes AND overlapping suffixes.
# A missing filter side means "" and overlaps everything. Pairs with an
# unresolvable event or filter value are skipped — overlap cannot be proven.

_pf_s3no_configs(name) := array.concat(array.concat(
	[c | some c in flatten_list(name, "Properties.NotificationConfiguration.QueueConfigurations")],
	[c | some c in flatten_list(name, "Properties.NotificationConfiguration.TopicConfigurations")]),
	[c | some c in flatten_list(name, "Properties.NotificationConfiguration.LambdaConfigurations")])

_pf_s3no_rules(c) := rules if {
	f := object.get(c, "Filter", null)
	is_object(f)
	k := object.get(f, "S3Key", null)
	is_object(k)
	rules := object.get(k, "Rules", [])
	is_array(rules)
}

_pf_s3no_rules(c) := [] if {
	object.get(c, "Filter", "__pf_absent") == "__pf_absent"
}

_pf_s3no_filter_val(c, kind) := v if {
	vs := [x | some r in _pf_s3no_rules(c); is_object(r); lower(object.get(r, "Name", "")) == kind; x := object.get(r, "Value", null)]
	count(vs) > 0
	v := vs[0]
}

_pf_s3no_filter_val(c, kind) := "" if {
	vs := [x | some r in _pf_s3no_rules(c); is_object(r); lower(object.get(r, "Name", "")) == kind; x := object.get(r, "Value", null)]
	count(vs) == 0
}

_pf_s3no_pre_overlap(a, b) if startswith(a, b)

_pf_s3no_pre_overlap(a, b) if startswith(b, a)

_pf_s3no_suf_overlap(a, b) if endswith(a, b)

_pf_s3no_suf_overlap(a, b) if endswith(b, a)

# "s3:ObjectCreated:*" covers "s3:ObjectCreated:Put"; drop the trailing "*"
# and prefix-match.
_pf_s3no_event_overlap(e1, e2) if e1 == e2

_pf_s3no_event_overlap(e1, e2) if {
	endswith(e1, ":*")
	startswith(e2, substring(e1, 0, count(e1) - 1))
}

_pf_s3no_event_overlap(e1, e2) if {
	endswith(e2, ":*")
	startswith(e1, substring(e2, 0, count(e2) - 1))
}

violation contains make_diag_full("pf-s3-notification-overlapping-filters", "ERROR", name,
	"Properties.NotificationConfiguration",
	sprintf("Two notification entries for overlapping event types ('%s' and '%s') have overlapping prefix/suffix filters; S3 rejects the configuration with \"Configuration is ambiguously defined. Cannot have overlapping suffixes in two rules if the prefixes are overlapping for the same event type.\"", [e1, e2]),
	"Make the prefixes or suffixes disjoint, or merge the two entries into one",
	"https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-filtering.html") if {
	some name in resources_of_type("AWS::S3::Bucket")
	cs := _pf_s3no_configs(name)
	some i, a in cs
	some j, b in cs
	i < j
	e1 := object.get(a.value, "Event", null)
	is_string(e1)
	e2 := object.get(b.value, "Event", null)
	is_string(e2)
	_pf_s3no_event_overlap(e1, e2)
	p1 := _pf_s3no_filter_val(a.value, "prefix")
	is_string(p1)
	p2 := _pf_s3no_filter_val(b.value, "prefix")
	is_string(p2)
	_pf_s3no_pre_overlap(p1, p2)
	s1 := _pf_s3no_filter_val(a.value, "suffix")
	is_string(s1)
	s2 := _pf_s3no_filter_val(b.value, "suffix")
	is_string(s2)
	_pf_s3no_suf_overlap(s1, s2)
}
