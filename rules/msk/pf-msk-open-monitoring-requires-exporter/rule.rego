package cdk_preflight

import rego.v1

# Both exporters are Required: No, so an empty Prometheus block is schema-valid and turns
# monitoring on with nothing to scrape; the create fails with "You must specify at least one type
# of exporter, either nodeExporter or jmxExporter. ... InvalidParameter: openMonitoring".
violation contains make_diag_full("pf-msk-open-monitoring-requires-exporter", "ERROR", name,
	"Properties.OpenMonitoring.Prometheus",
	"OpenMonitoring.Prometheus names no exporter; the create fails with \"You must specify at least one type of exporter, either nodeExporter or jmxExporter\"",
	"Declare JmxExporter or NodeExporter under Prometheus, or drop OpenMonitoring altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-prometheus.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	prom := object.get(props, ["OpenMonitoring", "Prometheus"], null)
	is_object(prom)
	named := [k | some k in object.keys(prom); k in {"JmxExporter", "NodeExporter"}]
	count(named) == 0
}
