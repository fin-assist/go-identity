package identity

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics counts rejected identity checks and reports JWKs skipped in the current
// key snapshots. It is safe for concurrent use. Labels are bounded even when its
// methods are accidentally called with untrusted data.
type Metrics struct {
	rejected *prometheus.CounterVec
	skipped  *prometheus.GaugeVec
}

// NewMetrics registers finassist_identity_rejected_total and
// finassist_identity_jwks_skipped_keys in the service registry. Duplicate
// registration is returned as an error, never resolved via global state.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	if reg == nil {
		return nil, errors.New("identity: registry required")
	}
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "finassist_identity_rejected_total", Help: "Rejected identity checks by bounded kind and reason."}, []string{"kind", "reason"})
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "finassist_identity_jwks_skipped_keys", Help: "JWKs skipped as unsupported in the current key snapshot, by bounded kind and reason."}, []string{"kind", "reason"})
	if err := reg.Register(c); err != nil {
		return nil, err
	}
	if err := reg.Register(g); err != nil {
		reg.Unregister(c)
		return nil, err
	}
	return &Metrics{c, g}, nil
}

// SkippedKeys implements KeyObserver. A kind other than user|service or an
// unknown reason is ignored rather than attributed to a real series.
func (m *Metrics) SkippedKeys(kind, reason string, count int) {
	if kind != "user" && kind != "service" {
		return
	}
	switch reason {
	case skipKty, skipCrv, skipAlg, skipUse, skipKeyOps, skipSize:
	default:
		return
	}
	m.skipped.WithLabelValues(kind, reason).Set(float64(max(count, 0)))
}

// Reject implements Observer without logging identity or credential material.
func (m *Metrics) Reject(kind, reason string) {
	switch kind {
	case "user", "service", "access":
	default:
		kind = "access"
	}
	switch reason {
	case "invalid", "expired", "signature", "audience", "issuer", "key_unavailable", "unknown_key", "forbidden", "user_id":
	default:
		reason = "invalid"
	}
	m.rejected.WithLabelValues(kind, reason).Inc()
}
