package identity

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics counts rejected identity checks. It is safe for concurrent use.
// Labels are bounded even when Reject is accidentally called with untrusted data.
type Metrics struct{ rejected *prometheus.CounterVec }

// NewMetrics registers finassist_identity_rejected_total in the service registry.
// Duplicate registration is returned as an error, never resolved via global state.
func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	if reg == nil {
		return nil, errors.New("identity: registry required")
	}
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: "finassist_identity_rejected_total", Help: "Rejected identity checks by bounded kind and reason."}, []string{"kind", "reason"})
	if err := reg.Register(c); err != nil {
		return nil, err
	}
	return &Metrics{c}, nil
}

// Reject implements Observer without logging identity or credential material.
func (m *Metrics) Reject(kind, reason string) {
	switch kind {
	case "user", "service", "access":
	default:
		kind = "access"
	}
	switch reason {
	case "invalid", "expired", "signature", "audience", "issuer", "key_unavailable", "forbidden", "user_id":
	default:
		reason = "invalid"
	}
	m.rejected.WithLabelValues(kind, reason).Inc()
}
