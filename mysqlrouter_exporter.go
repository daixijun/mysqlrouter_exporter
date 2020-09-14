// Copyright 2020 The Xijun Dai Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/rluisr/mysqlrouter-go"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	namespace = "mysqlrouter"
)

var (
	version   = "dev"
	commit    = "none"
	date      = "unknown"
	GoVersion = runtime.Version()
)

type Exporter struct {
	client *mysqlrouter.Client
	logger log.Logger

	scrapeTotal    prometheus.Counter
	scrapeDuration prometheus.Summary

	upDesc                                         *prometheus.Desc
	metadataDesc                                   *prometheus.Desc
	metadataConfigDesc                             *prometheus.Desc
	metadataConfigNodeDesc                         *prometheus.Desc
	metadataStatusDesc                             *prometheus.Desc
	routerStatusDesc                               *prometheus.Desc
	routeDesc                                      *prometheus.Desc
	routeActiveConnectionsDesc                     *prometheus.Desc
	routeTotalConnectionsDesc                      *prometheus.Desc
	routeBlockedHostsDesc                          *prometheus.Desc
	routeHealthDesc                                *prometheus.Desc
	routeDestinationsDesc                          *prometheus.Desc
	routeConnectionsByteFromServerDesc             *prometheus.Desc
	routeConnectionsByteToServerDesc               *prometheus.Desc
	routeConnectionsTimeStartedDesc                *prometheus.Desc
	routeConnectionsTimeConnectedToServerDesc      *prometheus.Desc
	routeConnectionsTimeLastSentToServerDesc       *prometheus.Desc
	routeConnectionsTimeLastReceivedFromServerDesc *prometheus.Desc
}

func NewExporter(uri, username, password string, logger log.Logger) (*Exporter, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}

	client, err := mysqlrouter.New(uri, username, password, true)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		client: client,
		logger: logger,

		scrapeTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "exporter_scrape_total",
			Help:      "Total number of times mysqlrouter was scraped for metrics.",
		}),
		scrapeDuration: prometheus.NewSummary(prometheus.SummaryOpts{
			Namespace: namespace,
			Name:      "exporter_scrape_duration_seconds",
			Help:      "Duration of mysqlrouter was scraped for metrics.",
		}),

		upDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "up"),
			"mysqlrouter up",
			nil,
			nil,
		),
		metadataDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "metadata"),
			"metadata list",
			[]string{"name"},
			nil,
		),
		metadataConfigDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "metadata_config"),
			"metadata config",
			[]string{"name", "cluster_name", "time_refresh_in_ms", "group_replication_id"},
			nil,
		),
		metadataConfigNodeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "metadata_config_node"),
			"metadata config node",
			[]string{"name", "router_host", "cluster_name", "hostname", "port"},
			nil,
		),
		metadataStatusDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "metadata_status"),
			"metadata status",
			[]string{"name", "refresh_failed", "time_last_refresh_succeeded", "last_refresh_hostname", "last_refresh_port"},
			nil,
		),
		routerStatusDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "router_status"),
			"MySQL Router information",
			[]string{"process_id", "product_edition", "time_started", "version", "hostname"},
			nil,
		),
		routeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route"),
			"route name",
			[]string{"name"},
			nil,
		),
		routeTotalConnectionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_total_connections"),
			"route total connections",
			[]string{"name", "router_hostname"},
			nil,
		),
		routeActiveConnectionsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_active_connections"),
			"route active connections",
			[]string{"name", "router_hostname"},
			nil,
		),
		routeBlockedHostsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_blocked_hosts"),
			"route blocked hosts",
			[]string{"name", "router_hostname"},
			nil,
		),
		routeHealthDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_health"),
			"0: not active, 1: active",
			[]string{"name", "router_hostname"},
			nil,
		),
		routeDestinationsDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_destinations"),
			"route destinations",
			[]string{"name", "address", "port"},
			nil,
		),
		routeConnectionsByteFromServerDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_byte_from_server"),
			"Route connections byte from server",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
		routeConnectionsByteToServerDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_byte_to_server"),
			"Route connections byte to server",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
		routeConnectionsTimeStartedDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_time_started"),
			"Route connections time started",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
		routeConnectionsTimeConnectedToServerDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_time_connected_to_server"),
			"Route connections time connected to server",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
		routeConnectionsTimeLastReceivedFromServerDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_time_last_received_from_server"),
			"Route connections time last received from server",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
		routeConnectionsTimeLastSentToServerDesc: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "", "route_connections_time_last_sent_to_server"),
			"Route connections time last sent to server",
			[]string{"name", "router_hostname", "source_address", "destination_address"},
			nil,
		),
	}, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.scrapeDuration.Desc()
	ch <- e.scrapeTotal.Desc()

	ch <- e.upDesc
	ch <- e.routerStatusDesc
	ch <- e.metadataDesc
	ch <- e.metadataConfigDesc
	ch <- e.metadataConfigNodeDesc
	ch <- e.metadataStatusDesc
	ch <- e.routeActiveConnectionsDesc
	ch <- e.routeBlockedHostsDesc
	ch <- e.routeConnectionsByteFromServerDesc
	ch <- e.routeConnectionsByteToServerDesc
	ch <- e.routeConnectionsTimeConnectedToServerDesc
	ch <- e.routeConnectionsTimeLastReceivedFromServerDesc
	ch <- e.routeConnectionsTimeLastSentToServerDesc
	ch <- e.routeConnectionsTimeStartedDesc
	ch <- e.routeDesc
	ch <- e.routeDestinationsDesc
	ch <- e.routeHealthDesc
	ch <- e.routeTotalConnectionsDesc
	ch <- e.routerStatusDesc
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.scrapeTotal.Inc()
	ch <- e.scrapeTotal

	up := e.scrape(ch)
	ch <- prometheus.MustNewConstMetric(e.upDesc, prometheus.GaugeValue, up)

	timeStartd := time.Now()
	dur := time.Since(timeStartd).Seconds()
	e.scrapeDuration.Observe(dur)
	ch <- e.scrapeDuration
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) (up float64) {

	// /api/20190715/router/status
	routerStatus, err := e.client.GetRouterStatus()
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to get router status", "err", err)
		return 0
	}
	ch <- prometheus.MustNewConstMetric(e.routerStatusDesc, prometheus.CounterValue, 1, strconv.Itoa(routerStatus.ProcessID), routerStatus.ProductEdition, routerStatus.TimeStarted.String(), routerStatus.Version, routerStatus.Hostname)

	// /api/20190715/metadata
	metadatas, err := e.client.GetAllMetadata()
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to list metadatas", "err", err)
		return 0
	}

	for _, metadata := range metadatas {
		ch <- prometheus.MustNewConstMetric(e.metadataDesc, prometheus.GaugeValue, 1, metadata.Name)

		// /api/20190715/metadata/{metadataName}/config
		metadataConfig, err := e.client.GetMetadataConfig(metadata.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Get metadata config failed", "metadata", metadata.Name, "err", err)
			return 0
		}
		ch <- prometheus.MustNewConstMetric(e.metadataConfigDesc, prometheus.GaugeValue, 1, metadata.Name, metadataConfig.ClusterName, strconv.Itoa(metadataConfig.TimeRefreshInMs), metadataConfig.GroupReplicationID)

		for _, metadataConfigNode := range metadataConfig.Nodes {
			ch <- prometheus.MustNewConstMetric(e.metadataConfigNodeDesc, prometheus.GaugeValue, 1, metadata.Name, routerStatus.Hostname, metadataConfig.ClusterName, metadataConfigNode.Hostname, strconv.Itoa(metadataConfigNode.Port))

		}

		// /api/20190715/metadata/{metadataName}/status
		metadataStatus, err := e.client.GetMetadataStatus(metadata.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Get metadata status failed", "metadata", metadata.Name, "err", err)
			return 0
		}
		ch <- prometheus.MustNewConstMetric(e.metadataStatusDesc, prometheus.GaugeValue, 1, metadata.Name, strconv.Itoa(metadataStatus.RefreshFailed), metadataStatus.TimeLastRefreshSucceeded.String(), metadataStatus.LastRefreshHostname, strconv.Itoa(metadataStatus.LastRefreshPort))
	}

	// /api/20190715/routes

	routes, err := e.client.GetAllRoutes()
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to fetch router list", "err", err)
		return 0
	}

	for _, route := range routes {
		ch <- prometheus.MustNewConstMetric(e.routeDesc, prometheus.GaugeValue, 1, route.Name)

		// /api/20190715/routes/{routeName}/health
		routeHealth, err := e.client.GetRouteHealth(route.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Failed to get route health", "route", route.Name, "err", err)
			return 0
		}
		if routeHealth.IsAlive {
			ch <- prometheus.MustNewConstMetric(e.routeHealthDesc, prometheus.GaugeValue, 1, route.Name, routerStatus.Hostname)
		} else {
			ch <- prometheus.MustNewConstMetric(e.routeHealthDesc, prometheus.GaugeValue, 0, route.Name, routerStatus.Hostname)
		}

		// /api/20190715/routes/{routeName}/status
		routeStatus, err := e.client.GetRouteStatus(route.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Failed to get route status", "route", route.Name, "err", err)
			return 0
		}
		ch <- prometheus.MustNewConstMetric(e.routeActiveConnectionsDesc, prometheus.GaugeValue, float64(routeStatus.ActiveConnections), route.Name, routerStatus.Hostname)
		ch <- prometheus.MustNewConstMetric(e.routeBlockedHostsDesc, prometheus.GaugeValue, float64(routeStatus.BlockedHosts), route.Name, routerStatus.Hostname)
		ch <- prometheus.MustNewConstMetric(e.routeTotalConnectionsDesc, prometheus.GaugeValue, float64(routeStatus.TotalConnections), route.Name, routerStatus.Hostname)

		// /api/20190715/routes/{routeName}/destinations
		routeDestinations, err := e.client.GetRouteDestinations(route.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Failed to get route destinations", "route", route.Name, "err", err)
			return 0
		}
		for _, dest := range routeDestinations {
			ch <- prometheus.MustNewConstMetric(e.routeDestinationsDesc, prometheus.GaugeValue, 1, route.Name, dest.Address, strconv.Itoa(dest.Port))
		}

		// /api/20190715/routes/{routeName}/connections
		routeConnections, err := e.client.GetRouteConnections(route.Name)
		if err != nil {
			level.Error(e.logger).Log("msg", "Failed to get route connections", "route", route.Name, "err", err)
			return 0
		}

		for _, conn := range routeConnections {
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsByteFromServerDesc, prometheus.GaugeValue, float64(conn.BytesFromServer), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsByteToServerDesc, prometheus.GaugeValue, float64(conn.BytesToServer), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsTimeStartedDesc, prometheus.GaugeValue, float64(conn.TimeStarted.Unix()*1000), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsTimeConnectedToServerDesc, prometheus.GaugeValue, float64(conn.TimeConnectedToServer.Unix()*1000), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsTimeLastReceivedFromServerDesc, prometheus.GaugeValue, float64(conn.TimeLastReceivedFromServer.Unix()*1000), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
			ch <- prometheus.MustNewConstMetric(e.routeConnectionsTimeLastSentToServerDesc, prometheus.GaugeValue, float64(conn.TimeLastSentToServer.Unix()*1000), route.Name, routerStatus.Hostname, conn.SourceAddress, conn.DestinationAddress)
		}
	}

	return 1
}

func main() {
	const pidFileHelpText = `Path to mysqlrouter pid file.
	If provided, the standard process metrics get exported for the mysqlrouter
	process, prefixed with 'mysqlrouter_process_...'. The mysqlrouter_process exporter
	needs to have read access to files owned by the mysqlrouter process. Depends on
	the availability of /proc.
	https://prometheus.io/docs/instrumenting/writing_clientlibs/#process-metrics.`

	var (
		listenAddress             = kingpin.Flag("web.listen-address", "Address to listen on for web interface and telemetry.").Default(":49152").String()
		metricsPath               = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		mysqlrouterScrapeURI      = kingpin.Flag("mysqlrouter.scrape-uri", "URI on which to scrape mysqlrouter.").Default("http://localhost:8081").OverrideDefaultFromEnvar("MYSQLROUTER_URI").String()
		mysqlrouterScrapeUsername = kingpin.Flag("mysqlrouter.username", "Flag that username for the scrape URI").Default("").OverrideDefaultFromEnvar("MYSQLROUTER_USERNAME").String()
		mysqlrouterScrapePassword = kingpin.Flag("mysqlrouter.password", "Flag that password for the scrape URI").Default("").OverrideDefaultFromEnvar("MYSQLROUTER_PASSWORD").String()
		mysqlrouterPidFile        = kingpin.Flag("mysqlrouter.pid-file", pidFileHelpText).Default("").String()

		// mysqlrouterSSLVerify = kingpin.Flag("mysqlrouter.ssl-verify", "Flag that enables SSL certificate verification for the scrape URI").Default("true").Bool()
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	// kingpin.Version(version.Print("mysqlrouter_exporter"))
	kingpin.Version(fmt.Sprintf("mysqlrouter_exporter version=%s, (commit: %s, buildDate: %s, goVersion: %s)", version, commit, date, GoVersion))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting mysqlrouter_exporter", "version", version)
	// level.Info(logger).Log("msg", "Build context", "context", version.BuildContext())

	exporter, err := NewExporter(*mysqlrouterScrapeURI, *mysqlrouterScrapeUsername, *mysqlrouterScrapePassword, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating an exporter", "err", err)
		os.Exit(1)
	}

	prometheus.MustRegister(exporter)
	// prometheus.MustRegister(version.NewCollector("mysqlrouter_exporter"))

	if *mysqlrouterPidFile != "" {
		procExporter := prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{
			PidFn: func() (int, error) {
				content, err := ioutil.ReadFile(*mysqlrouterPidFile)
				if err != nil {
					return 0, fmt.Errorf("can't read pid file: %s", err)
				}
				value, err := strconv.Atoi(strings.TrimSpace(string(content)))
				if err != nil {
					return 0, fmt.Errorf("can't parse pid file: %s", err)
				}
				return value, nil
			},
			Namespace: namespace,
		})
		prometheus.MustRegister(procExporter)
	}

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>mysqlrouter Exporter</title></head>
             <body>
             <h1>mysqlrouter Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
