package cdk_preflight

import rego.v1

_pf_fhidt_routed(name, path) if {
	some [nm, p, _, t, _] in _pf_fhlib_procs
	nm == name
	p == path
	t in {"Lambda", "MetadataExtraction"}
}

violation contains make_diag_full("pf-firehose-iceberg-default-table-config", "ERROR", name,
	"Properties.IcebergDestinationConfiguration.DestinationTableConfigurationList",
	"the Iceberg destination has no destination table configuration and no Lambda or MetadataExtraction processor to route records; the stream create fails with \"A single default destination table configuration must be provided when both Lambda and MetadataExtraction processors are not provided\"",
	"Add one DestinationTableConfigurationList entry, or route records with a Lambda / MetadataExtraction processor",
	"https://docs.aws.amazon.com/firehose/latest/dev/apache-iceberg-destination.html") if {
	some [name, path, c] in _pf_fhlib_dests
	path == "Properties.IcebergDestinationConfiguration"
	count(object.get(c, "DestinationTableConfigurationList", [])) == 0
	not _pf_fhidt_routed(name, path)
}
