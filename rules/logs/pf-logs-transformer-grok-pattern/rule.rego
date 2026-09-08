package cdk_preflight

import rego.v1

# ponytail: an allowlist taken from the documented "Supported grok patterns"
# table. A pattern AWS adds later would false-positive until this set is
# updated.
_pf_lggp_patterns := {
	"APACHE_ACCESS_LOG",
	"ARN",
	"BASE10NUM",
	"BASE16NUM",
	"CISCOMAC",
	"COMMONMAC",
	"DATA",
	"DATE",
	"DATESTAMP",
	"DATESTAMP_EVENTLOG",
	"DATESTAMP_OTHER",
	"DATESTAMP_RFC2822",
	"DATESTAMP_RFC822",
	"DATE_EU",
	"DATE_US",
	"DAY",
	"GREEDYDATA",
	"GREEDYDATA_MULTILINE",
	"HOST",
	"HOSTNAME",
	"HOSTPORT",
	"HOUR",
	"HTTPDATE",
	"INT",
	"IP",
	"IPORHOST",
	"IPV4",
	"IPV6",
	"ISO8601_SECOND",
	"ISO8601_TIMEZONE",
	"LOGLEVEL",
	"MAC",
	"MINUTE",
	"MONTH",
	"MONTHDAY",
	"MONTHNUM",
	"MONTHNUM2",
	"NGINX_ACCESS_LOG",
	"NONNEGINT",
	"NOTSPACE",
	"NUMBER",
	"PATH",
	"POSINT",
	"PROG",
	"QUOTEDSTRING",
	"SECOND",
	"SPACE",
	"SYSLOG5424",
	"SYSLOGFACILITY",
	"SYSLOGHOST",
	"SYSLOGPROG",
	"SYSLOGTIMESTAMP",
	"TIME",
	"TIMESTAMP_ISO8601",
	"TTY",
	"TZ",
	"UNIXPATH",
	"URI",
	"URIHOST",
	"URIPARAM",
	"URIPATH",
	"URIPATHPARAM",
	"URIPROTO",
	"URN",
	"USERNAME",
	"UUID",
	"WINDOWSMAC",
	"WINPATH",
	"WORD",
	"YEAR",
}

violation contains make_diag_full("pf-logs-transformer-grok-pattern", "ERROR", name,
	"Properties.TransformerConfig",
	sprintf("The grok match references the unknown pattern '%s'; PutTransformer fails with \"No definition for key '%s' found\"", [pattern, pattern]),
	"Use one of the supported grok pattern names (WORD, NUMBER, TIMESTAMP_ISO8601, ...)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch-Logs-Transformation-Configurable.html") if {
	some name in resources_of_type("AWS::Logs::Transformer")
	some item in flatten_list(name, "Properties.TransformerConfig")
	processor := item.value
	is_object(processor)
	grok := object.get(processor, "Grok", null)
	is_object(grok)
	match := object.get(grok, "Match", null)
	is_string(match)
	some ref in regex.find_n(`%\{[A-Za-z_0-9]+`, match, -1)
	pattern := substring(ref, 2, count(ref) - 2)
	not pattern in _pf_lggp_patterns
}
