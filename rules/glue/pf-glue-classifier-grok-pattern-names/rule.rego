package cdk_preflight

import rego.v1

# The built-in set is exactly the list the user guide prints; every one of the
# 74 names compiles and every logstash name outside it does not (measured against
# CreateClassifier, 2026-09-14). Names the template defines in CustomPatterns
# count as known; a CustomPatterns value the engine cannot resolve skips the rule.
_pf_gluegrok_builtin := {"BASE10NUM", "BASE16FLOAT", "BASE16NUM", "BOOLEAN", "CISCOMAC", "CISCOTIMESTAMP", "COMBINEDAPACHELOG", "COMMONAPACHELOG", "COMMONAPACHELOG_DATATYPED", "COMMONMAC", "DATA", "DATESTAMP_EU", "DATESTAMP_EVENTLOG", "DATESTAMP_OTHER", "DATESTAMP_RFC2822", "DATESTAMP_RFC822", "DATESTAMP_US", "DATE_EU", "DATE_US", "DAY", "GREEDYDATA", "HOST", "HOSTNAME", "HOSTPORT", "HOUR", "HTTPDATE", "INT", "IP", "IPORHOST", "IPV4", "IPV6", "ISO8601_SECOND", "ISO8601_TIMEZONE", "LOGLEVEL", "MAC", "MESSAGESLOG", "MINUTE", "MONTH", "MONTHDAY", "MONTHNUM", "MONTHNUM2", "NONNEGINT", "NOTSPACE", "NUMBER", "PATH", "POSINT", "PROG", "QS", "QUOTEDSTRING", "SECOND", "SPACE", "SYSLOGBASE", "SYSLOGFACILITY", "SYSLOGHOST", "SYSLOGPROG", "SYSLOGTIMESTAMP", "TIME", "TIMESTAMP_ISO8601", "TTY", "TZ", "UNIXPATH", "URI", "URIHOST", "URIPARAM", "URIPATH", "URIPATHPARAM", "URIPROTO", "USER", "USERNAME", "UUID", "WINDOWSMAC", "WINPATH", "WORD", "YEAR"}

_pf_gluegrok_defined(grok) := d if {
	cp := grok.CustomPatterns
	_pf_gluelib_lit(cp)
	d := {n |
		some line in split(cp, "\n")
		n := regex.split(`\s+`, trim_space(line))[0]
		n != ""
	}
}

_pf_gluegrok_defined(grok) := set() if {
	object.get(grok, "CustomPatterns", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-glue-classifier-grok-pattern-names", "ERROR", name,
	"Properties.GrokClassifier.GrokPattern",
	sprintf("GrokPattern references %%{%s}, which is neither an AWS Glue built-in pattern nor defined in CustomPatterns; CreateClassifier fails with \"Grok pattern cannot be compiled.\"", [ref]),
	sprintf("Use a built-in pattern name or define %s in CustomPatterns", [ref]),
	"https://docs.aws.amazon.com/glue/latest/dg/custom-classifier.html") if {
	some name in resources_of_type("AWS::Glue::Classifier")
	grok := _pf_gluelib_classifier(name, "GrokClassifier")
	gp := grok.GrokPattern
	_pf_gluelib_lit(gp)
	defined := _pf_gluegrok_defined(grok)
	some m in regex.find_all_string_submatch_n(`%\{([A-Za-z0-9_]+)`, gp, -1)
	ref := m[1]
	not ref in _pf_gluegrok_builtin
	not ref in defined
}
