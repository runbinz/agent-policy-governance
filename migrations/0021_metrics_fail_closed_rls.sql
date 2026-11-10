-- Global aggregates require a privileged function owner that can read all rows.
-- row_security=off grants no bypass: an incorrectly configured owner errors
-- instead of publishing silently scoped/empty business metrics.
ALTER FUNCTION read_service_metrics() SET row_security=off;
ALTER FUNCTION read_service_metrics_base() SET row_security=off;
