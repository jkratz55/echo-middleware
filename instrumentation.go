package middleware

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	latencyLabels      = []string{"method", "path", "status"}
	sizeLabels         = []string{"method", "path"}
	defaultSizeBuckets = []float64{131072, 262144, 524288, 1048576, 1572864, 2097152}
)

type PrometheusConfig struct {

	// Allows the middleware to inspect the request and decide to skip the
	// middleware.
	Skipper middleware.Skipper

	Namespace      string
	Subsystem      string
	LatencyBuckets []float64
	SizeBuckets    []float64
	ConstLabels    map[string]string
	Registerer     prometheus.Registerer
}

func Prometheus() echo.MiddlewareFunc {
	return PrometheusWithConfig(PrometheusConfig{
		Skipper:        nil,
		Namespace:      "http",
		Subsystem:      "",
		LatencyBuckets: prometheus.ExponentialBuckets(0.050, 2, 6),
		SizeBuckets:    defaultSizeBuckets,
		ConstLabels:    nil,
		Registerer:     nil,
	})
}

func PrometheusWithConfig(conf PrometheusConfig) echo.MiddlewareFunc {

	if len(conf.LatencyBuckets) == 0 {
		conf.LatencyBuckets = prometheus.ExponentialBuckets(0.050, 2, 6)
	}
	if len(conf.SizeBuckets) == 0 {
		conf.SizeBuckets = defaultSizeBuckets
	}

	latencyHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   conf.Namespace,
		Subsystem:   conf.Subsystem,
		Name:        "request_duration_seconds",
		Help:        "Time in seconds to process an HTTP request",
		ConstLabels: conf.ConstLabels,
		Buckets:     conf.LatencyBuckets,
	}, latencyLabels)
	requestSizeHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   conf.Namespace,
		Subsystem:   conf.Subsystem,
		Name:        "request_size_bytes",
		Help:        "Estimated size of the HTTP request in bytes",
		ConstLabels: conf.ConstLabels,
		Buckets:     conf.SizeBuckets,
	}, sizeLabels)
	responseSizeHistogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   conf.Namespace,
		Subsystem:   conf.Subsystem,
		Name:        "response_size_bytes",
		Help:        "Estimated size of the HTTP response in bytes",
		ConstLabels: conf.ConstLabels,
		Buckets:     conf.SizeBuckets,
	}, sizeLabels)

	if conf.Registerer == nil {
		prometheus.MustRegister(latencyHistogram, requestSizeHistogram, responseSizeHistogram)
	} else {
		conf.Registerer.MustRegister(latencyHistogram, requestSizeHistogram, responseSizeHistogram)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			// If a Skipper is defined and returns true skip to next handler in
			// the chain.
			if conf.Skipper != nil && conf.Skipper(c) {
				return next(c)
			}

			requestSize := estimateRequestSize(c.Request())

			start := time.Now()
			err := next(c)
			elapsed := time.Since(start).Seconds()

			url := c.Path()
			if url == "" {
				url = c.Request().URL.Path
			}

			status := c.Response().Status
			if err != nil {
				var httpError *echo.HTTPError
				if errors.As(err, &httpError) {
					status = httpError.Code
				}
				if status == 0 || status == http.StatusOK {
					status = http.StatusInternalServerError
				}
			}

			latencyHistogram.WithLabelValues(c.Request().Method, url, strconv.Itoa(status)).
				Observe(elapsed)
			requestSizeHistogram.WithLabelValues(c.Request().Method, url).
				Observe(float64(requestSize))
			responseSizeHistogram.WithLabelValues(c.Request().Method, url).
				Observe(float64(c.Response().Size))

			return err
		}
	}
}

func estimateRequestSize(r *http.Request) int {
	size := 0
	if r.URL != nil {
		size = len(r.URL.Path)
	}

	size += len(r.Method)
	size += len(r.Proto)
	for name, values := range r.Header {
		size += len(name)
		for _, value := range values {
			size += len(value)
		}
	}
	size += len(r.Host)

	if r.ContentLength != -1 {
		size += int(r.ContentLength)
	}
	return size
}
