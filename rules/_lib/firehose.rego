package cdk_preflight

import rego.v1

# Shared traversal for AWS::KinesisFirehose::DeliveryStream. Every rule in
# rules/firehose reads the delivery stream through these helpers: the
# destination blocks are ten sibling keys with near-identical inner shapes,
# and the interesting constraints live in the S3 prefix DSL and in the
# processor list, neither of which any schema layer can express.
#
# Rego has no recursion, so nesting is expanded explicitly. The prefix
# carriers are two levels deep (destination, then S3Configuration /
# S3BackupConfiguration) and that is the whole tree - no deeper case exists
# in the resource schema.

_pf_fhlib_dest_keys := {
	"S3DestinationConfiguration",
	"ExtendedS3DestinationConfiguration",
	"RedshiftDestinationConfiguration",
	"ElasticsearchDestinationConfiguration",
	"AmazonopensearchserviceDestinationConfiguration",
	"AmazonOpenSearchServerlessDestinationConfiguration",
	"SplunkDestinationConfiguration",
	"HttpEndpointDestinationConfiguration",
	"SnowflakeDestinationConfiguration",
	"IcebergDestinationConfiguration",
}

_pf_fhlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# [logical id, property path, destination configuration]
_pf_fhlib_dests contains [name, path, c] if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	p := _pf_fhlib_props(name)
	some k in _pf_fhlib_dest_keys
	c := object.get(p, k, null)
	is_object(c)
	path := sprintf("Properties.%s", [k])
}

# Blocks that carry a Prefix / ErrorOutputPrefix pair: the destination
# itself and its nested S3 configurations.
_pf_fhlib_prefixed contains [name, path, c] if {
	some [name, path, c] in _pf_fhlib_dests
}

_pf_fhlib_prefixed contains [name, sub, s] if {
	some [name, path, c] in _pf_fhlib_dests
	some k in {"S3Configuration", "S3BackupConfiguration"}
	s := object.get(c, k, null)
	is_object(s)
	sub := sprintf("%s.%s", [path, k])
}

# [logical id, destination path, index, type, raw processor object]
_pf_fhlib_procs contains [name, path, i, t, pr] if {
	some [name, path, c] in _pf_fhlib_dests
	pc := object.get(c, "ProcessingConfiguration", null)
	is_object(pc)
	ps := object.get(pc, "Processors", null)
	is_array(ps)
	some i, pr in ps
	is_object(pr)
	t := object.get(pr, "Type", null)
}

# All values given for one processor parameter name (empty when absent).
_pf_fhlib_params(pr, k) := vs if {
	ps := object.get(pr, "Parameters", [])
	is_array(ps)
	vs := [v |
		some p in ps
		is_object(p)
		object.get(p, "ParameterName", null) == k
		v := object.get(p, "ParameterValue", null)
	]
}

_pf_fhlib_has_param(pr, k) if count(_pf_fhlib_params(pr, k)) > 0

# ---- the !{namespace:value} prefix DSL ----------------------------------

_pf_fhlib_exprs(s) := regex.find_n(`!\{[^{}]*\}`, s, -1)

_pf_fhlib_ns(e) := ns if {
	i := indexof(e, ":")
	i > 2
	ns := substring(e, 2, i - 2)
}

_pf_fhlib_val(e) := v if {
	i := indexof(e, ":")
	i > 2
	v := substring(e, i + 1, (count(e) - i) - 2)
}

# A "!{" that is not part of a well formed expression.
_pf_fhlib_stray(s) if {
	rest := regex.replace(s, `!\{[a-zA-Z]+:[^{}]*\}`, "")
	contains(rest, "!{")
}

_pf_fhlib_namespaces := {"timestamp", "firehose", "partitionKeyFromQuery", "partitionKeyFromLambda"}

# Joda pattern letters the service rejects with "Invalid conversion
# character" (measured 2026-09-10 over all 52 ASCII letters).
_pf_fhlib_ts_bad := {"C", "I", "J", "P", "R", "T", "U", "V", "b", "f", "i", "j", "l", "o", "p", "r", "t"}

_pf_fhlib_dp_enabled(name, path) if {
	some [nm, p, c] in _pf_fhlib_dests
	nm == name
	p == path
	dp := object.get(c, "DynamicPartitioningConfiguration", null)
	is_object(dp)
	coerce_to_bool(object.get(dp, "Enabled", false)) == true
}

# A user-written literal, not an intrinsic (those arrive as marker objects).
_pf_fhlib_lit(v) if {
	is_string(v)
	not startswith(v, "__pf")
}
