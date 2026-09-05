package cdk_preflight

import rego.v1

_pf_wafld_url := "https://docs.aws.amazon.com/waf/latest/developerguide/logging-destinations.html"

_pf_wafld_fix := "Give the LogGroup / Bucket / DeliveryStream an explicit name starting with aws-waf-logs- (CloudFormation-generated names never do), create it in the same account and region as the web ACL (us-east-1 for CLOUDFRONT scope), and list exactly one destination"

_pf_wafld_msg := "PutLoggingConfiguration fails with \"The ARN isn't valid. A valid ARN begins with arn: and includes other information separated by colons or slashes.\""

_pf_wafld_dests(name) := d if {
	d := input.resources[name].properties.LogDestinationConfigs
	is_array(d)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, "Properties.LogDestinationConfigs",
	sprintf("%d destinations listed; a web ACL takes exactly one logging destination (PutLoggingConfiguration fails with WAFLimitsExceededException)", [count(d)]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	d := _pf_wafld_dests(name)
	count(d) != 1
}

# region the logged web ACL lives in
_pf_wafld_region(name) := parts[3] if {
	parts := _pf_waflib_arn(_pf_waflib_lit(name, "Properties.ResourceArn"))
}

_pf_wafld_region(name) := r if {
	x := _pf_waflib_getatt(input.resources[name].properties.ResourceArn)
	x in resources_of_type("AWS::WAFv2::WebACL")
	r := _pf_waflib_region(x)
}

_pf_wafld_path(j) := sprintf("Properties.LogDestinationConfigs[%d]", [j])

# ---- literal destination ARNs ----
_pf_wafld_lit contains [name, j, s, parts] if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	d := _pf_wafld_dests(name)
	some j
	s := d[j]
	is_string(s)
	parts := _pf_waflib_arn(s)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("'%s' is not an ARN; destinations are log group, S3 bucket or Firehose delivery stream ARNs", [s]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	d := _pf_wafld_dests(name)
	some j
	s := d[j]
	is_string(s)
	not _pf_waflib_arn(s)
}

# destination name by service: [service, name]
_pf_wafld_name(parts) := ["logs", parts[6]] if {
	parts[2] == "logs"
	parts[5] == "log-group"
	count(parts) >= 7
}

_pf_wafld_name(parts) := ["s3", split(parts[5], "/")[0]] if parts[2] == "s3"

_pf_wafld_name(parts) := ["firehose", split(parts[5], "/")[1]] if {
	parts[2] == "firehose"
	startswith(parts[5], "deliverystream/")
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("'%s' is not a log group, S3 bucket or Firehose delivery stream ARN; %s", [s, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, s, parts] in _pf_wafld_lit
	not _pf_wafld_name(parts)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("%s name '%s' does not start with aws-waf-logs- (case-sensitive); %s", [svc, n, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, s, parts] in _pf_wafld_lit
	[svc, n] := _pf_wafld_name(parts)
	not startswith(n, "aws-waf-logs-")
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("%s destination is in region '%s' but the web ACL is in '%s'; PutLoggingConfiguration fails with WAFNonexistentItemException", [svc, parts[3], region]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, s, parts] in _pf_wafld_lit
	[svc, n] := _pf_wafld_name(parts)
	svc != "s3"
	region := _pf_wafld_region(name)
	parts[3] != region
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("%s destination belongs to account %s but the web ACL deploys to account %s; PutLoggingConfiguration fails with WAFNonexistentItemException", [svc, parts[4], account]),
	_pf_wafld_fix, _pf_wafld_url) if {
	account := data.cdk_preflight.deploy_account
	some [name, j, s, parts] in _pf_wafld_lit
	[svc, n] := _pf_wafld_name(parts)
	svc != "s3"
	parts[4] != account
}

# ---- in-template destinations (Fn::GetAtt X.Arn) ----
_pf_wafld_ref contains [name, j, x] if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	d := _pf_wafld_dests(name)
	some j
	x := _pf_waflib_getatt(d[j])
	input.resources[x]
}

_pf_wafld_name_prop := {"AWS::Logs::LogGroup": "LogGroupName", "AWS::S3::Bucket": "BucketName", "AWS::KinesisFirehose::DeliveryStream": "DeliveryStreamName"}

_pf_wafld_ref_type(x) := t if {
	some t in object.keys(_pf_wafld_name_prop)
	x in resources_of_type(t)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("references %s, which is not a log group, S3 bucket or Firehose delivery stream; %s", [x, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, x] in _pf_wafld_ref
	not _pf_wafld_ref_type(x)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("%s has no %s, so CloudFormation generates a name like <stack>-%s-XXXX that cannot start with aws-waf-logs-; %s", [x, prop, x, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, x] in _pf_wafld_ref
	t := _pf_wafld_ref_type(x)
	prop := _pf_wafld_name_prop[t]
	object.get(input.resources[x].properties, prop, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, _pf_wafld_path(j),
	sprintf("%s.%s '%s' does not start with aws-waf-logs- (case-sensitive); %s", [x, prop, n, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some [name, j, x] in _pf_wafld_ref
	t := _pf_wafld_ref_type(x)
	prop := _pf_wafld_name_prop[t]
	n := resolve(x, sprintf("Properties.%s", [prop]))
	is_string(n)
	not startswith(n, "aws-waf-logs-")
}

# ---- ResourceArn must be a web ACL ----
violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, "Properties.ResourceArn",
	sprintf("'%s' is not the ARN of a WAFv2 web ACL; %s", [s, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	s := _pf_waflib_lit(name, "Properties.ResourceArn")
	not regex.match("^arn:[^:]+:wafv2:[^:]+:[^:]*:(global|regional)/webacl/", s)
}

violation contains make_diag_full("pf-wafv2-logging-destination", "ERROR", name, "Properties.ResourceArn",
	sprintf("references %s, which is not an AWS::WAFv2::WebACL; %s", [x, _pf_wafld_msg]),
	_pf_wafld_fix, _pf_wafld_url) if {
	some name in resources_of_type("AWS::WAFv2::LoggingConfiguration")
	x := _pf_waflib_getatt(input.resources[name].properties.ResourceArn)
	input.resources[x]
	not x in resources_of_type("AWS::WAFv2::WebACL")
}
