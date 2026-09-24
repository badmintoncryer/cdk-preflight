package cdk_preflight

import rego.v1

# Shared helpers for the CloudWatch Synthetics rules. Absence can only be proven on
# the preprocessed document (resolve() is undefined both for a missing key and for
# an unresolvable token, see AGENTS.md), so "is the property written" always goes
# through _pf_synlib_present / _pf_synlib_absent. Loaded ahead of every rule
# (BUNDLED_LIBS); never emits diagnostics.

_pf_synlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# path is an array of keys, e.g. ["Code", "S3Key"].
_pf_synlib_present(name, path) if {
	object.get(_pf_synlib_props(name), path, "__pf_absent") != "__pf_absent"
}

_pf_synlib_absent(name, path) if {
	object.get(_pf_synlib_props(name), path, "__pf_absent") == "__pf_absent"
}

# The literal string the document carries at path, if it carries one. Undefined for a
# missing key and for a token ({"Ref": ...} is an object), which is what makes it safe
# to compare against an enum: resolve() hands back a logical id for a Ref-to-resource
# and would read as a bogus enum value. The default must not be a string - is_string()
# would accept the sentinel and the rule would fire on every resource that omits the key.
_pf_synlib_str(name, path) := v if {
	v := object.get(_pf_synlib_props(name), path, null)
	is_string(v)
}

# Schedule.Expression as [count, unit]. Undefined for cron(), for an unresolved token
# and for anything that is not exactly "rate(<digits> <word>)".
_pf_synlib_rate(expr) := [n, unit] if {
	is_string(expr)
	startswith(expr, "rate(")
	endswith(expr, ")")
	parts := split(substring(expr, 5, count(expr) - 6), " ")
	count(parts) == 2
	n := to_number(parts[0])
	unit := parts[1]
}

_pf_synlib_rate_units := {"minute", "minutes", "hour"}

_pf_synlib_rate_minutes(n, unit) := n if unit in {"minute", "minutes"}

_pf_synlib_rate_minutes(n, unit) := n * 60 if unit == "hour"

_pf_synlib_encryption_modes := {"SSE_S3", "SSE_KMS"}

# Does Code point at an S3 object at all? Its own rule body so that a caller never
# carries two `some .. in` iterations (two in one body take the whole pack down).
_pf_synlib_code_has_s3(name) if {
	some k in ["S3Bucket", "S3Key", "S3ObjectVersion"]
	_pf_synlib_present(name, ["Code", k])
}

# ---- slice 2 (#71) ----------------------------------------------------------

# Does Code point at a script at all? Own rule body so a caller never carries two
# `some .. in` iterations (two in one body take the whole pack down, AGENTS.md).
_pf_synlib_code_source(name) if {
	some k in ["Script", "S3Bucket", "SourceLocationArn"]
	_pf_synlib_present(name, ["Code", k])
}

# The region segment of an ARN, when it names the given service.
_pf_synlib_arn_region(v, service) := r if {
	is_string(v)
	parts := split(v, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == service
	r := parts[3]
	r != ""
}

# Runtimes the deprecation table lists as deprecated. Table read 2026-09-24;
# CloudWatch Synthetics only ever adds rows, so a stale copy under-reports and
# never false-positives.
_pf_synlib_deprecated_runtimes := {
	"syn-1.0",
	"syn-nodejs-2.0-beta",
	"syn-nodejs-2.0",
	"syn-nodejs-2.1",
	"syn-nodejs-2.2",
	"syn-nodejs-puppeteer-3.0",
	"syn-nodejs-puppeteer-3.1",
	"syn-nodejs-puppeteer-3.2",
	"syn-nodejs-puppeteer-3.3",
	"syn-nodejs-puppeteer-3.4",
	"syn-nodejs-puppeteer-3.5",
	"syn-nodejs-puppeteer-3.6",
	"syn-nodejs-puppeteer-3.7",
	"syn-nodejs-puppeteer-3.8",
	"syn-nodejs-puppeteer-3.9",
	"syn-nodejs-puppeteer-4.0",
	"syn-nodejs-puppeteer-5.0",
	"syn-nodejs-puppeteer-5.1",
	"syn-nodejs-puppeteer-5.2",
	"syn-nodejs-puppeteer-6.0",
	"syn-nodejs-puppeteer-6.1",
	"syn-nodejs-puppeteer-6.2",
	"syn-nodejs-puppeteer-7.0",
	"syn-python-selenium-1.0",
	"syn-python-selenium-1.1",
	"syn-python-selenium-1.2",
	"syn-python-selenium-1.3",
	"syn-python-selenium-2.0",
	"syn-python-selenium-2.1",
	"syn-python-selenium-3.0",
	"syn-python-selenium-4.0",
	"syn-python-selenium-4.1",
	"syn-python-selenium-5.0",
	"syn-python-selenium-5.1",
}

# Lambda's reserved environment variable names (list read 2026-09-24). A canary run
# is a Lambda function, so RunConfig.EnvironmentVariables inherits the restriction.
# Lambda's *unreserved* defaults (TZ, PATH, AWS_XRAY_*, NODE_OPTIONS, ...) may be set
# and are deliberately absent.
_pf_synlib_reserved_env := {
	"_HANDLER",
	"_X_AMZN_TRACE_ID",
	"AWS_ACCESS_KEY",
	"AWS_ACCESS_KEY_ID",
	"AWS_DEFAULT_REGION",
	"AWS_EXECUTION_ENV",
	"AWS_LAMBDA_FUNCTION_MEMORY_SIZE",
	"AWS_LAMBDA_FUNCTION_NAME",
	"AWS_LAMBDA_FUNCTION_VERSION",
	"AWS_LAMBDA_INITIALIZATION_TYPE",
	"AWS_LAMBDA_LOG_GROUP_NAME",
	"AWS_LAMBDA_LOG_STREAM_NAME",
	"AWS_LAMBDA_MAX_CONCURRENCY",
	"AWS_LAMBDA_METADATA_API",
	"AWS_LAMBDA_METADATA_TOKEN",
	"AWS_LAMBDA_RUNTIME_API",
	"AWS_REGION",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"LAMBDA_RUNTIME_DIR",
	"LAMBDA_TASK_ROOT",
}

# RunConfig.EnvironmentVariables as written, when it is an object.
_pf_synlib_env(name) := e if {
	e := object.get(_pf_synlib_props(name), ["RunConfig", "EnvironmentVariables"], null)
	is_object(e)
}
