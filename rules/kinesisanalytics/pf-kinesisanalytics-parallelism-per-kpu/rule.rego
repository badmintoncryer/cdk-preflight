package cdk_preflight

import rego.v1

# The schema carries the minimum (1) but no maximum; the service caps it at 8.
violation contains make_diag_full("pf-kinesisanalytics-parallelism-per-kpu", "ERROR", name,
	"Properties.ApplicationConfiguration.FlinkApplicationConfiguration.ParallelismConfiguration.ParallelismPerKPU",
	sprintf("ParallelismPerKPU is %v; CreateApplication fails with \"FlinkApplicationParallelismPerKPU ... should not be larger than the supported limit 8\"", [n]),
	"Use 8 or fewer parallel tasks per KPU",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ParallelismConfiguration.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	p := resolve(name, "Properties.ApplicationConfiguration.FlinkApplicationConfiguration.ParallelismConfiguration.ParallelismPerKPU")
	n := to_number(p)
	n > 8
}
