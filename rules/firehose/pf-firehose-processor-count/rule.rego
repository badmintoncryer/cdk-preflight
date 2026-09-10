package cdk_preflight

import rego.v1

_pf_fhpc_count(c) := n if {
	pc := object.get(c, "ProcessingConfiguration", null)
	is_object(pc)
	coerce_to_bool(object.get(pc, "Enabled", false)) == true
	ps := object.get(pc, "Processors", [])
	is_array(ps)
	n := count(ps)
}

violation contains make_diag_full("pf-firehose-processor-count", "ERROR", name,
	sprintf("%s.ProcessingConfiguration.Processors", [path]),
	sprintf("processing is enabled with %d processors; the stream create fails with \"A maximum of 5 and a minimum of 1 processor needs to be supplied when processing is enabled.\"", [n]),
	"Supply between one and five processors, or disable processing",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_ProcessingConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_dests
	n := _pf_fhpc_count(c)
	_pf_fhpc_out(n)
}

_pf_fhpc_out(n) if n < 1

_pf_fhpc_out(n) if n > 5
