package middleware

import (
	"bytes"
	"io"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"go.uber.org/zap"
)

// LoggerConfig controls the behavior of the logging middlewares.
type LoggerConfig struct {
	// Skipper defines a function to skip the middleware. The zero-value/default
	// is to always execute the middleware.
	Skipper middleware.Skipper
	// Configures/extracts the value used for the "correlation_id" value that is
	// logged. The zero-value/default behavior is to use X-Request-ID from the
	// request HTTP header.
	CorrelationIDExtractor func(c echo.Context) string
	// Controls if HTTP headers are logged for the request and response. The
	// zero-value/default behavior is to not log the HTTP headers.
	//
	// Notice: Logging HTTP headers can contain sensitive information and may
	// be a security/privacy risk.
	Headers bool
	// Controls if the HTTP request body is logged. The zero-value/default behavior
	// is to not log the HTTP request body.
	//
	// Notice: The HTTP request body can contain sensitive information and may
	// be a security/privacy risk to log.
	RequestBody bool
	// Controls if the HTTP response body is logged. The zero-value/default behavior
	// is to not log the HTTP response body.
	//
	// Notice: The HTTP response body can contain sensitive information and may
	// be a security/privacy risk to log.
	ResponseBody bool
}

// ZapLogger returns a middleware that logs HTTP requests using Uber Zap
// with a sane default configuration.
func ZapLogger(logger *zap.Logger) echo.MiddlewareFunc {
	return ZapLoggerWithConfig(logger, LoggerConfig{})
}

func ZapLoggerWithConfig(logger *zap.Logger, config LoggerConfig) echo.MiddlewareFunc {
	if logger == nil {
		panic("a valid zap.Logger is required, illegal use of API")
	}
	if config.Skipper == nil {
		config.Skipper = func(c echo.Context) bool {
			return false
		}
	}
	if config.CorrelationIDExtractor == nil {
		config.CorrelationIDExtractor = func(c echo.Context) string {
			return c.Request().Header.Get(echo.HeaderXRequestID)
		}
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()

			reqBody := make([]byte, 0)
			if config.RequestBody && c.Request().Body != nil {
				reqBody, _ = io.ReadAll(c.Request().Body)
				c.Request().Body = io.NopCloser(bytes.NewBuffer(reqBody))
			}

			resBody := new(bytes.Buffer)
			if config.ResponseBody {
				multiWriter := io.MultiWriter(c.Response().Writer, resBody)
				writer := &bodyDumpResponseWriter{Writer: multiWriter, ResponseWriter: c.Response().Writer}
				c.Response().Writer = writer
			}

			start := time.Now()
			err := next(c)
			if err != nil {
				c.Error(err)
			}
			elapsed := time.Since(start).Milliseconds()

			fields := []zap.Field{
				zap.String("correlation_id", config.CorrelationIDExtractor(c)),
				zap.String("method", req.Method),
				zap.String("host", req.Host),
				zap.String("uri", req.URL.String()),
				zap.String("path", req.URL.Path),
				zap.String("route", c.Path()),
				zap.String("user_agent", req.UserAgent()),
				zap.String("referer", req.Referer()),
				zap.String("remote_ip", c.RealIP()),
				zap.Int("status", res.Status),
				zap.Int64("latency_ms", elapsed),
				zap.String("bytes_in", req.Header.Get(echo.HeaderContentLength)),
				zap.String("bytes_out", strconv.FormatInt(res.Size, 10)),
				zap.Error(err),
			}

			if config.Headers {
				fields = append(fields, zap.Any("request_header", req.Header),
					zap.Any("response_header", res.Header()))
			}
			if config.RequestBody {
				fields = append(fields, zap.String("request_body", string(reqBody)))
			}
			if config.ResponseBody {
				fields = append(fields, zap.String("response_body", resBody.String()))
			}

			logger.Info("HTTP request processed", fields...)
			return nil
		}
	}
}

func ZeroLogger(logger zerolog.Logger) echo.MiddlewareFunc {
	return ZeroLoggerWithConfig(logger, LoggerConfig{})
}

func ZeroLoggerWithConfig(logger zerolog.Logger, config LoggerConfig) echo.MiddlewareFunc {
	if config.Skipper == nil {
		config.Skipper = func(c echo.Context) bool {
			return false
		}
	}
	if config.CorrelationIDExtractor == nil {
		config.CorrelationIDExtractor = func(c echo.Context) string {
			return c.Request().Header.Get(echo.HeaderXRequestID)
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()

			reqBody := make([]byte, 0)
			if config.RequestBody && c.Request().Body != nil {
				reqBody, _ = io.ReadAll(c.Request().Body)
				c.Request().Body = io.NopCloser(bytes.NewBuffer(reqBody))
			}

			resBody := new(bytes.Buffer)
			if config.ResponseBody {
				multiWriter := io.MultiWriter(c.Response().Writer, resBody)
				writer := &bodyDumpResponseWriter{Writer: multiWriter, ResponseWriter: c.Response().Writer}
				c.Response().Writer = writer
			}

			start := time.Now()
			err := next(c)
			if err != nil {
				c.Error(err)
			}
			elapsed := time.Since(start).Milliseconds()

			event := logger.Info().
				Str("correlation_id", config.CorrelationIDExtractor(c)).
				Str("method", req.Method).
				Str("host", req.Host).
				Str("uri", req.URL.String()).
				Str("path", req.URL.Path).
				Str("route", c.Path()).
				Str("user_agent", req.UserAgent()).
				Str("referer", req.Referer()).
				Str("remote_ip", c.RealIP()).
				Int("status", res.Status).
				Int64("latency_ms", elapsed).
				Str("bytes_in", req.Header.Get(echo.HeaderContentLength)).
				Str("bytes_out", strconv.FormatInt(res.Size, 10))

			if err != nil {
				event.Err(err)
			}

			if config.Headers {
				event.Any("request_header", req.Header).
					Any("response_header", res.Header())
			}
			if config.RequestBody {
				event.Str("request_body", string(reqBody))
			}
			if config.ResponseBody {
				event.Str("response_body", resBody.String())
			}

			event.Send()
			return nil
		}
	}
}
