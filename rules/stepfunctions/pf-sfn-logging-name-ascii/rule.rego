package cdk_preflight

import rego.v1

_pf_sfnlogname_url := "https://docs.aws.amazon.com/step-functions/latest/apireference/API_CreateStateMachine.html"

_pf_sfnlogname_fix := "Rename the state machine to [0-9A-Za-z._-]+ or turn logging off"

# The name itself accepts non-ASCII characters (measured: 'テスト' creates
# fine); it is the log delivery resourceId pattern ^[0-9A-Za-z.\/\-_:]+$
# (quoted verbatim from the service error) that rejects it once
# LoggingConfiguration.Level is not OFF. The class mirrors that pattern; the
# / and : it admits are already rejected by the name itself (pf-sfn-name-charset).
violation contains make_diag_full("pf-sfn-logging-name-ascii", "ERROR", name,
	"Properties.StateMachineName",
	sprintf("StateMachineName '%s' contains characters outside [0-9A-Za-z._-] while LoggingConfiguration.Level is %s; CreateStateMachine fails with \"InvalidLoggingConfiguration: ... Value 'arn:...:stateMachine:%s' at 'resourceId' failed to satisfy constraint: Member must satisfy regular expression pattern\"", [n, lvl, n]),
	_pf_sfnlogname_fix, _pf_sfnlogname_url) if {
	some name in resources_of_type("AWS::StepFunctions::StateMachine")
	lvl := resolve(name, "Properties.LoggingConfiguration.Level")
	is_string(lvl)
	lvl != "OFF"
	n := resolve(name, "Properties.StateMachineName")
	is_string(n)
	not regex.match("^[0-9A-Za-z._:/-]+$", n)
}
