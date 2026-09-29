package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
)

// opAudit names a payment operation for auditOp: its operation name, the
// event of a completed call, and whether its cryptography runs in this
// service (metered for the Operations metrics). ISO 20022 sign, verify,
// encrypt and decrypt run in keycore, which meters them.
type opAudit struct {
	op      string
	success string
	metered bool
}

// auditOp emits one event per payment operation when it returns: a.success
// with the operation's details, or audit.payment.<op>_refused (permission,
// policy, limits) / audit.payment.<op>_failed with the reason. A verify
// that ran and found a mismatch is a success with its result in details.
func (s *Service) auditOp(ctx context.Context, a opAudit, tenantID string, start time.Time, err error, details map[string]interface{}) {
	subject, tenantID := a.success, strings.TrimSpace(tenantID)
	if details == nil {
		details = map[string]interface{}{}
	}
	if err != nil {
		result, reason, severity := "failure", "", "info"
		var se serviceError
		if errors.As(err, &se) {
			reason = se.Code
			switch se.HTTPStatus {
			case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests:
				result, severity = "refused", "warning"
			}
		}
		subject = "audit.payment." + a.op + "_failed"
		if result == "refused" {
			subject = "audit.payment." + a.op + "_refused"
		}
		details = map[string]interface{}{"result": result, "reason": reason, "error": err.Error(), "severity": severity}
	}
	if a.metered {
		pkgaudit.Metered(details, a.op, start)
	} else {
		details["duration_ms"] = pkgaudit.DurationMS(start)
	}
	_ = s.publishAudit(ctx, subject, tenantID, details)
}

// auditResult is an event's result: data["result"] when the caller set
// one, else success.
func auditResult(data map[string]interface{}) string {
	if r, ok := data["result"].(string); ok && r != "" {
		return r
	}
	return "success"
}
