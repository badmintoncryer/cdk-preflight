package cdk_preflight

import rego.v1

# Shared helpers for the CloudWatch Logs rules.

_pf_lglib_absent(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") == "__pf_absent"
}

_pf_lglib_arn(v) := parts if {
	is_string(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) >= 6
}

# A property typed as Json arrives as an object; the same property written as a
# string is also accepted by CloudFormation.
_pf_lglib_json(v) := v if is_object(v)

_pf_lglib_json(v) := obj if {
	is_string(v)
	json.is_valid(v)
	obj := json.unmarshal(v)
	is_object(obj)
}

_pf_lglib_dpp(name) := obj if {
	obj := _pf_lglib_json(resolve(name, "Properties.DataProtectionPolicy"))
}

_pf_lglib_ia(g) if resolve(g, "Properties.LogGroupClass") == "INFREQUENT_ACCESS"

# Log groups in this template that a value points at. A Ref or GetAtt resolves
# to the target's logical id; a literal string can be the LogGroupName.
# ponytail: an ARN built with Fn::Sub over a Ref is undefined under resolve()
# and is skipped.
_pf_lglib_named(g, v) if g == v

_pf_lglib_named(g, v) if resolve(g, "Properties.LogGroupName") == v

_pf_lglib_groups(v) := gs if {
	is_string(v)
	gs := {g |
		some g in resources_of_type("AWS::Logs::LogGroup")
		_pf_lglib_named(g, v)
	}
}

# flatten_list drops the __kind marker, so a Ref / GetAtt element of a list
# arrives as {"__ref": "<logical id>"} rather than a string.
_pf_lglib_ref(v) := v if is_string(v)

_pf_lglib_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", null)
	is_string(r)
}

_pf_lglib_ia_target(name, path) if {
	some g in _pf_lglib_groups(resolve(name, path))
	_pf_lglib_ia(g)
}

# The service a subscription filter delivers to, from a literal ARN or from an
# in-template resource reached through Ref / GetAtt.
_pf_lglib_dest_types := {
	"AWS::Kinesis::Stream": "kinesis",
	"AWS::KinesisFirehose::DeliveryStream": "firehose",
	"AWS::Lambda::Function": "lambda",
	"AWS::Logs::Destination": "logs",
}

_pf_lglib_dest_vendor(name) := vendor if {
	d := resolve(name, "Properties.DestinationArn")
	parts := _pf_lglib_arn(d)
	vendor := parts[2]
}

_pf_lglib_dest_vendor(name) := vendor if {
	d := resolve(name, "Properties.DestinationArn")
	is_string(d)
	not startswith(d, "arn:")
	some t, v in _pf_lglib_dest_types
	d in resources_of_type(t)
	vendor := v
}

# An IAM policy document rendered into a string property.
_pf_lgdpj_iam(p) if {
	json.is_valid(p)
	obj := json.unmarshal(p)
	is_object(obj)
	is_array(object.get(obj, "Statement", null))
}
