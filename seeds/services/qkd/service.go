package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store   Store
	keycore KeyCoreClient
	events  EventPublisher
	mek     []byte
}

func NewService(store Store, keycore KeyCoreClient, events EventPublisher, mek []byte) *Service {
	if len(mek) < 32 {
		mek = []byte("0123456789ABCDEF0123456789ABCDEF")
	}
	return &Service{
		store:   store,
		keycore: keycore,
		events:  events,
		mek:     append([]byte{}, mek[:32]...),
	}
}

func (s *Service) requireServiceEnabled(cfg QKDConfig) error {
	if cfg.ServiceEnabled {
		return nil
	}
	return newServiceError(http.StatusServiceUnavailable, "qkd_service_disabled", "qkd service is disabled")
}

func (s *Service) requireETSIEnabled(cfg QKDConfig) error {
	if err := s.requireServiceEnabled(cfg); err != nil {
		return err
	}
	if cfg.ETSIAPIEnabled {
		return nil
	}
	return newServiceError(http.StatusServiceUnavailable, "etsi_api_disabled", "etsi qkd api is disabled")
}

func (s *Service) log(ctx context.Context, tenantID string, action string, level string, message string, meta map[string]interface{}) {
	if s.store == nil {
		return
	}
	entry := QKDLogEntry{
		ID:        newID("qlog"),
		TenantID:  strings.TrimSpace(tenantID),
		Action:    strings.TrimSpace(action),
		Level:     strings.TrimSpace(level),
		Message:   strings.TrimSpace(message),
		Meta:      meta,
		CreatedAt: time.Now().UTC(),
	}
	_ = s.store.InsertLog(ctx, entry)
}

func (s *Service) GetConfig(ctx context.Context, tenantID string) (QKDConfig, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return QKDConfig{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	cfg, err := s.store.GetConfig(ctx, tenantID)
	if errors.Is(err, errNotFound) {
		cfg = normalizeQKDConfig(QKDConfig{TenantID: tenantID})
		if err := s.store.UpsertConfig(ctx, cfg); err != nil {
			return QKDConfig{}, err
		}
		return cfg, nil
	}
	if err != nil {
		return QKDConfig{}, err
	}
	return normalizeQKDConfig(cfg), nil
}

func (s *Service) UpdateConfig(ctx context.Context, cfg QKDConfig) (QKDConfig, error) {
	cfg = normalizeQKDConfig(cfg)
	if cfg.TenantID == "" {
		return QKDConfig{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if err := s.store.UpsertConfig(ctx, cfg); err != nil {
		return QKDConfig{}, err
	}
	out, err := s.GetConfig(ctx, cfg.TenantID)
	if err != nil {
		return QKDConfig{}, err
	}
	_ = s.publishAudit(ctx, "audit.qkd.config_updated", cfg.TenantID, map[string]interface{}{
		"qber_threshold":     out.QBERThreshold,
		"pool_low_threshold": out.PoolLowThreshold,
		"pool_capacity":      out.PoolCapacity,
		"auto_inject":        out.AutoInject,
		"service_enabled":    out.ServiceEnabled,
		"etsi_api_enabled":   out.ETSIAPIEnabled,
		"protocol":           out.Protocol,
		"distance_km":        out.DistanceKM,
	})
	s.log(ctx, cfg.TenantID, "config_updated", "info", "QKD runtime configuration updated", map[string]interface{}{
		"qber_threshold":     out.QBERThreshold,
		"pool_low_threshold": out.PoolLowThreshold,
		"pool_capacity":      out.PoolCapacity,
		"auto_inject":        out.AutoInject,
		"service_enabled":    out.ServiceEnabled,
		"etsi_api_enabled":   out.ETSIAPIEnabled,
		"protocol":           out.Protocol,
		"distance_km":        out.DistanceKM,
	})
	return out, nil
}

func (s *Service) ReceiveEncKeys(ctx context.Context, tenantID string, slaveSAEID string, req ReceiveKeysRequest) (ReceiveKeysResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	slaveSAEID = strings.TrimSpace(slaveSAEID)
	if tenantID == "" || slaveSAEID == "" {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return ReceiveKeysResponse{}, err
	}
	if err := s.requireETSIEnabled(cfg); err != nil {
		return ReceiveKeysResponse{}, err
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		deviceID = "device_" + slaveSAEID
	}
	deviceName := strings.TrimSpace(req.DeviceName)
	if deviceName == "" {
		deviceName = deviceID
	}
	linkStatus := normalizeLinkStatus(req.LinkStatus)
	if linkStatus == "" {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "invalid link_status")
	}
	oldDevice, oldErr := s.store.GetDevice(ctx, tenantID, deviceID)

	if len(req.Keys) == 0 {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "keys are required")
	}

	accepted := make([]string, 0, len(req.Keys))
	discarded := make([]string, 0)
	for i, item := range req.Keys {
		raw, err := decodeB64Key(item.MaterialB64)
		if err != nil {
			return ReceiveKeysResponse{}, err
		}
		keySizeBits := len(raw) * 8
		keyID := strings.TrimSpace(item.KeyID)
		if keyID == "" {
			keyID = newID("qk")
		}
		env, err := pkgcrypto.EncryptEnvelope(s.mek, raw)
		pkgcrypto.Zeroize(raw)
		if err != nil {
			return ReceiveKeysResponse{}, err
		}

		status := KeyStatusAvailable
		if item.QBER > cfg.QBERThreshold {
			status = KeyStatusDiscarded
			discarded = append(discarded, keyID)
		} else {
			accepted = append(accepted, keyID)
		}
		key := QKDKey{
			ID:            keyID,
			TenantID:      tenantID,
			DeviceID:      deviceID,
			SlaveSAEID:    slaveSAEID,
			ExternalKeyID: defaultExternalKeyID(item.KeyID, i),
			KeySizeBits:   keySizeBits,
			QBER:          item.QBER,
			Status:        status,
			WrappedDEK:    env.WrappedDEK,
			WrappedDEKIV:  env.WrappedDEKIV,
			Ciphertext:    env.Ciphertext,
			DataIV:        env.DataIV,
		}
		if err := s.store.CreateKey(ctx, key); err != nil {
			return ReceiveKeysResponse{}, err
		}
		if status == KeyStatusDiscarded {
			_ = s.publishAudit(ctx, "audit.qkd.key_discarded", tenantID, map[string]interface{}{
				"key_id":       keyID,
				"slave_sae_id": slaveSAEID,
				"device_id":    deviceID,
				"qber":         item.QBER,
				"threshold":    cfg.QBERThreshold,
			})
			continue
		}
		_ = s.publishAudit(ctx, "audit.qkd.key_received", tenantID, map[string]interface{}{
			"key_id":       keyID,
			"slave_sae_id": slaveSAEID,
			"device_id":    deviceID,
			"qber":         item.QBER,
		})
		if cfg.AutoInject {
			_, _ = s.InjectKey(ctx, keyID, InjectRequest{
				TenantID: tenantID,
				Name:     "qkd-auto-" + keyID,
				Purpose:  "encrypt",
				Consume:  true,
			})
		}
	}

	qberAvg, _ := s.store.GetDeviceQBERAvg(ctx, tenantID, deviceID)
	keyRate := float64(len(req.Keys))
	if err := s.store.UpsertDevice(ctx, QKDDevice{
		ID:         deviceID,
		TenantID:   tenantID,
		Name:       deviceName,
		Role:       normalizeRole(req.Role),
		SlaveSAEID: slaveSAEID,
		LinkStatus: linkStatus,
		KeyRate:    keyRate,
		QBERAvg:    qberAvg,
		LastSeenAt: time.Now().UTC(),
	}); err != nil {
		return ReceiveKeysResponse{}, err
	}
	if oldErr == nil && oldDevice.LinkStatus != linkStatus {
		_ = s.publishAudit(ctx, "audit.qkd.link_status_changed", tenantID, map[string]interface{}{
			"device_id":    deviceID,
			"slave_sae_id": slaveSAEID,
			"from":         oldDevice.LinkStatus,
			"to":           linkStatus,
		})
	}
	_ = s.checkPoolWarning(ctx, tenantID, slaveSAEID, cfg)
	s.log(ctx, tenantID, "keys_received", "info", "QKD keys received from upstream peer", map[string]interface{}{
		"slave_sae_id":     slaveSAEID,
		"device_id":        deviceID,
		"accepted_count":   len(accepted),
		"discarded_count":  len(discarded),
		"link_status":      linkStatus,
		"qber_threshold":   cfg.QBERThreshold,
		"service_enabled":  cfg.ServiceEnabled,
		"etsi_api_enabled": cfg.ETSIAPIEnabled,
	})
	return ReceiveKeysResponse{
		SlaveSAEID:      slaveSAEID,
		AcceptedKeyIDs:  accepted,
		DiscardedKeyIDs: discarded,
		AcceptedCount:   len(accepted),
		DiscardedCount:  len(discarded),
	}, nil
}

func (s *Service) GetSlaveStatus(ctx context.Context, tenantID string, slaveSAEID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	slaveSAEID = strings.TrimSpace(slaveSAEID)
	if tenantID == "" || slaveSAEID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireETSIEnabled(cfg); err != nil {
		return nil, err
	}
	available, err := s.store.CountAvailableKeys(ctx, tenantID, slaveSAEID)
	if err != nil {
		return nil, err
	}
	devices, err := s.store.ListDevices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	linkStatus := LinkStatusDown
	keyRate := 0.0
	qber := 0.0
	matched := 0
	for _, d := range devices {
		if d.SlaveSAEID != slaveSAEID {
			continue
		}
		matched++
		if d.LinkStatus == LinkStatusUp {
			linkStatus = LinkStatusUp
		}
		keyRate += d.KeyRate
		qber += d.QBERAvg
	}
	if matched > 0 {
		qber = qber / float64(matched)
	}
	out := map[string]interface{}{
		"slave_sae_id":        slaveSAEID,
		"available_key_count": available,
		"key_size_bits":       256,
		"link_status":         linkStatus,
		"key_rate":            round3(keyRate),
		"qber_avg":            round4(qber),
	}
	s.log(ctx, tenantID, "etsi_status", "debug", "ETSI status queried", map[string]interface{}{
		"slave_sae_id":        slaveSAEID,
		"available_key_count": available,
		"link_status":         linkStatus,
		"key_rate":            out["key_rate"],
		"qber_avg":            out["qber_avg"],
	})
	return out, nil
}

func (s *Service) RetrieveDecKeys(ctx context.Context, tenantID string, slaveSAEID string, req RetrieveKeysRequest) (RetrieveKeysResponse, error) {
	tenantID = strings.TrimSpace(tenantID)
	slaveSAEID = strings.TrimSpace(slaveSAEID)
	if tenantID == "" || slaveSAEID == "" {
		return RetrieveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return RetrieveKeysResponse{}, err
	}
	if err := s.requireETSIEnabled(cfg); err != nil {
		return RetrieveKeysResponse{}, err
	}

	var keys []QKDKey
	if len(req.KeyIDs) > 0 {
		keys, err = s.store.GetKeysByIDs(ctx, tenantID, req.KeyIDs, []string{KeyStatusAvailable, KeyStatusReserved})
		if err != nil {
			return RetrieveKeysResponse{}, err
		}
	} else {
		count := req.Count
		if count <= 0 || count > 100 {
			count = 1
		}
		keys, err = s.store.ListAvailableKeysBySlave(ctx, tenantID, slaveSAEID, count)
		if err != nil {
			return RetrieveKeysResponse{}, err
		}
	}
	if len(keys) == 0 {
		return RetrieveKeysResponse{SlaveSAEID: slaveSAEID, Keys: []RetrievedKey{}}, nil
	}
	status := normalizeKeyStatus(req.MarkStatus)
	if status == "" {
		status = KeyStatusConsumed
	}
	out := make([]RetrievedKey, 0, len(keys))
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		if k.SlaveSAEID != slaveSAEID {
			continue
		}
		raw, err := s.decryptKeyMaterial(k)
		if err != nil {
			return RetrieveKeysResponse{}, err
		}
		out = append(out, RetrievedKey{
			KeyID:       k.ID,
			KeyB64:      base64.StdEncoding.EncodeToString(raw),
			QBER:        k.QBER,
			KeySizeBits: len(raw) * 8,
		})
		pkgcrypto.Zeroize(raw)
		ids = append(ids, k.ID)
	}
	if err := s.store.UpdateKeysStatus(ctx, tenantID, ids, []string{KeyStatusAvailable, KeyStatusReserved}, status); err != nil {
		return RetrieveKeysResponse{}, err
	}
	_ = s.checkPoolWarning(ctx, tenantID, slaveSAEID, cfg)
	_ = s.publishAudit(ctx, "audit.qkd.keys_retrieved", tenantID, map[string]interface{}{
		"slave_sae_id": slaveSAEID,
		"count":        len(out),
		"mark_status":  status,
		"key_ids":      ids,
	})
	s.log(ctx, tenantID, "keys_retrieved", "info", "QKD keys retrieved for consumption", map[string]interface{}{
		"slave_sae_id": slaveSAEID,
		"count":        len(out),
		"mark_status":  status,
	})
	return RetrieveKeysResponse{
		SlaveSAEID: slaveSAEID,
		Keys:       out,
	}, nil
}

func (s *Service) OpenConnect(ctx context.Context, req OpenConnectRequest) (OpenConnectResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.SlaveSAEID = strings.TrimSpace(req.SlaveSAEID)
	req.AppID = strings.TrimSpace(req.AppID)
	if req.TenantID == "" || req.SlaveSAEID == "" {
		return OpenConnectResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	cfg, err := s.GetConfig(ctx, req.TenantID)
	if err != nil {
		return OpenConnectResponse{}, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return OpenConnectResponse{}, err
	}
	if req.DeviceID == "" {
		req.DeviceID = "session_" + req.SlaveSAEID
	}
	session := QKDSession{
		ID:         newID("qsess"),
		TenantID:   req.TenantID,
		DeviceID:   req.DeviceID,
		SlaveSAEID: req.SlaveSAEID,
		AppID:      req.AppID,
		Status:     "open",
		OpenedAt:   time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return OpenConnectResponse{}, err
	}
	device, err := s.store.GetDevice(ctx, req.TenantID, req.DeviceID)
	if errors.Is(err, errNotFound) {
		_ = s.store.UpsertDevice(ctx, QKDDevice{
			ID:         req.DeviceID,
			TenantID:   req.TenantID,
			Name:       req.DeviceID,
			Role:       "consumer",
			SlaveSAEID: req.SlaveSAEID,
			LinkStatus: LinkStatusUp,
			LastSeenAt: time.Now().UTC(),
		})
	} else if err == nil && device.LinkStatus != LinkStatusUp {
		_ = s.store.UpdateDeviceLinkStatus(ctx, req.TenantID, req.DeviceID, LinkStatusUp, device.KeyRate, device.QBERAvg)
		_ = s.publishAudit(ctx, "audit.qkd.link_status_changed", req.TenantID, map[string]interface{}{
			"device_id":    req.DeviceID,
			"slave_sae_id": req.SlaveSAEID,
			"from":         device.LinkStatus,
			"to":           LinkStatusUp,
		})
	}
	_ = s.publishAudit(ctx, "audit.qkd.session_opened", req.TenantID, map[string]interface{}{
		"session_id":   session.ID,
		"device_id":    req.DeviceID,
		"slave_sae_id": req.SlaveSAEID,
		"app_id":       req.AppID,
	})
	s.log(ctx, req.TenantID, "session_opened", "info", "QKD connect session opened", map[string]interface{}{
		"session_id":    session.ID,
		"device_id":     req.DeviceID,
		"slave_sae_id":  req.SlaveSAEID,
		"app_id":        req.AppID,
		"service_state": cfg.ServiceEnabled,
	})
	return OpenConnectResponse{
		SessionID: session.ID,
		Status:    "open",
	}, nil
}

func (s *Service) GetKey(ctx context.Context, req GetKeyRequest) (GetKeyResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.TenantID == "" || req.SessionID == "" {
		return GetKeyResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and session_id are required")
	}
	cfg, err := s.GetConfig(ctx, req.TenantID)
	if err != nil {
		return GetKeyResponse{}, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return GetKeyResponse{}, err
	}
	sess, err := s.store.GetSession(ctx, req.TenantID, req.SessionID)
	if err != nil {
		return GetKeyResponse{}, err
	}
	if !strings.EqualFold(sess.Status, "open") {
		return GetKeyResponse{}, newServiceError(http.StatusBadRequest, "session_closed", "session is not open")
	}
	if req.Count <= 0 || req.Count > 100 {
		req.Count = 1
	}
	keys, err := s.RetrieveDecKeys(ctx, req.TenantID, sess.SlaveSAEID, RetrieveKeysRequest{
		TenantID:   req.TenantID,
		Count:      req.Count,
		MarkStatus: KeyStatusConsumed,
	})
	if err != nil {
		return GetKeyResponse{}, err
	}
	_ = s.store.TouchSession(ctx, req.TenantID, req.SessionID)
	_ = s.publishAudit(ctx, "audit.qkd.session_get_key", req.TenantID, map[string]interface{}{
		"session_id": req.SessionID,
		"count":      len(keys.Keys),
	})
	s.log(ctx, req.TenantID, "session_get_key", "info", "QKD session key retrieval", map[string]interface{}{
		"session_id": req.SessionID,
		"count":      len(keys.Keys),
	})
	return GetKeyResponse{
		SessionID: req.SessionID,
		Keys:      keys.Keys,
	}, nil
}

func (s *Service) CloseConnect(ctx context.Context, req CloseConnectRequest) (CloseConnectResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.TenantID == "" || req.SessionID == "" {
		return CloseConnectResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and session_id are required")
	}
	cfg, err := s.GetConfig(ctx, req.TenantID)
	if err != nil {
		return CloseConnectResponse{}, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return CloseConnectResponse{}, err
	}
	sess, err := s.store.GetSession(ctx, req.TenantID, req.SessionID)
	if err != nil {
		return CloseConnectResponse{}, err
	}
	if err := s.store.CloseSession(ctx, req.TenantID, req.SessionID); err != nil {
		return CloseConnectResponse{}, err
	}
	device, err := s.store.GetDevice(ctx, req.TenantID, sess.DeviceID)
	if err == nil && device.LinkStatus != LinkStatusDown {
		_ = s.store.UpdateDeviceLinkStatus(ctx, req.TenantID, sess.DeviceID, LinkStatusDown, device.KeyRate, device.QBERAvg)
		_ = s.publishAudit(ctx, "audit.qkd.link_status_changed", req.TenantID, map[string]interface{}{
			"device_id":    sess.DeviceID,
			"slave_sae_id": sess.SlaveSAEID,
			"from":         device.LinkStatus,
			"to":           LinkStatusDown,
		})
	}
	_ = s.publishAudit(ctx, "audit.qkd.session_closed", req.TenantID, map[string]interface{}{
		"session_id":   req.SessionID,
		"device_id":    sess.DeviceID,
		"slave_sae_id": sess.SlaveSAEID,
	})
	s.log(ctx, req.TenantID, "session_closed", "info", "QKD connect session closed", map[string]interface{}{
		"session_id":   req.SessionID,
		"device_id":    sess.DeviceID,
		"slave_sae_id": sess.SlaveSAEID,
	})
	return CloseConnectResponse{
		SessionID: req.SessionID,
		Status:    "closed",
	}, nil
}

func (s *Service) ListDevices(ctx context.Context, tenantID string) ([]QKDDevice, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return nil, err
	}
	return s.store.ListDevices(ctx, tenantID)
}

func (s *Service) DeviceStatus(ctx context.Context, tenantID string, deviceID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	deviceID = strings.TrimSpace(deviceID)
	if tenantID == "" || deviceID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and device id are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return nil, err
	}
	device, err := s.store.GetDevice(ctx, tenantID, deviceID)
	if err != nil {
		return nil, err
	}
	available, err := s.store.CountAvailableKeys(ctx, tenantID, device.SlaveSAEID)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"id":                  device.ID,
		"tenant_id":           device.TenantID,
		"name":                device.Name,
		"role":                device.Role,
		"slave_sae_id":        device.SlaveSAEID,
		"link_status":         device.LinkStatus,
		"key_rate":            round3(device.KeyRate),
		"qber_avg":            round4(device.QBERAvg),
		"available_key_count": available,
		"last_seen_at":        device.LastSeenAt,
	}
	_ = s.publishAudit(ctx, "audit.qkd.health_check", tenantID, map[string]interface{}{
		"device_id":    device.ID,
		"slave_sae_id": device.SlaveSAEID,
		"link_status":  device.LinkStatus,
		"key_rate":     out["key_rate"],
		"qber_avg":     out["qber_avg"],
		"pool":         available,
	})
	s.log(ctx, tenantID, "device_status", "debug", "QKD device status queried", map[string]interface{}{
		"device_id":           device.ID,
		"slave_sae_id":        device.SlaveSAEID,
		"available_key_count": available,
		"link_status":         device.LinkStatus,
	})
	return out, nil
}

func (s *Service) Overview(ctx context.Context, tenantID string, slaveSAEID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	slaveSAEID = strings.TrimSpace(slaveSAEID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return nil, err
	}
	devices, err := s.store.ListDevices(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	filtered := make([]QKDDevice, 0, len(devices))
	if slaveSAEID == "" && len(devices) > 0 {
		slaveSAEID = devices[0].SlaveSAEID
	}
	for _, d := range devices {
		if slaveSAEID == "" || d.SlaveSAEID == slaveSAEID {
			filtered = append(filtered, d)
		}
	}
	available, err := s.store.CountAvailableKeys(ctx, tenantID, slaveSAEID)
	if err != nil {
		return nil, err
	}
	total, err := s.store.CountTotalKeys(ctx, tenantID, slaveSAEID)
	if err != nil {
		return nil, err
	}
	createdToday, err := s.store.CountKeysCreatedToday(ctx, tenantID, slaveSAEID)
	if err != nil {
		return nil, err
	}
	usedToday, err := s.store.CountKeysUsedToday(ctx, tenantID, slaveSAEID)
	if err != nil {
		return nil, err
	}
	linkStatus := LinkStatusDown
	keyRate := 0.0
	qberSum := 0.0
	source := ""
	destination := ""
	for _, d := range filtered {
		if d.LinkStatus == LinkStatusUp {
			linkStatus = LinkStatusUp
		}
		keyRate += d.KeyRate
		qberSum += d.QBERAvg
		role := strings.ToLower(strings.TrimSpace(d.Role))
		if source == "" && (role == "alice" || role == "provider" || role == "peer") {
			source = d.Name
		}
		if destination == "" && (role == "bob" || role == "consumer") {
			destination = d.Name
		}
	}
	if source == "" && len(filtered) > 0 {
		source = filtered[0].Name
	}
	if destination == "" && len(filtered) > 1 {
		destination = filtered[len(filtered)-1].Name
	}
	qberAvg := 0.0
	if len(filtered) > 0 {
		qberAvg = qberSum / float64(len(filtered))
	}
	utilization := 0.0
	if cfg.PoolCapacity > 0 {
		utilization = (float64(available) / float64(cfg.PoolCapacity)) * 100
	}
	out := map[string]interface{}{
		"tenant_id":    tenantID,
		"slave_sae_id": slaveSAEID,
		"config": map[string]interface{}{
			"service_enabled":    cfg.ServiceEnabled,
			"etsi_api_enabled":   cfg.ETSIAPIEnabled,
			"protocol":           cfg.Protocol,
			"distance_km":        round3(cfg.DistanceKM),
			"qber_threshold":     round4(cfg.QBERThreshold),
			"pool_low_threshold": cfg.PoolLowThreshold,
			"pool_capacity":      cfg.PoolCapacity,
			"auto_inject":        cfg.AutoInject,
			"updated_at":         cfg.UpdatedAt.UTC(),
		},
		"status": map[string]interface{}{
			"active":              linkStatus == LinkStatusUp,
			"link_status":         linkStatus,
			"source":              source,
			"destination":         destination,
			"key_rate":            round3(keyRate),
			"qber_avg":            round4(qberAvg),
			"keys_received_today": createdToday,
		},
		"pool": map[string]interface{}{
			"available_keys": available,
			"used_today":     usedToday,
			"total_keys":     total,
			"pool_fill_pct":  round3(utilization),
			"low":            available < cfg.PoolLowThreshold,
		},
	}
	s.log(ctx, tenantID, "overview", "debug", "QKD overview queried", map[string]interface{}{
		"slave_sae_id":  slaveSAEID,
		"available":     available,
		"used_today":    usedToday,
		"service_state": cfg.ServiceEnabled,
	})
	return out, nil
}

func (s *Service) ListKeys(ctx context.Context, tenantID string, slaveSAEID string, statuses []string, limit int) ([]map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	slaveSAEID = strings.TrimSpace(slaveSAEID)
	if tenantID == "" || slaveSAEID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return nil, err
	}
	items, err := s.store.ListKeys(ctx, tenantID, slaveSAEID, statuses, limit)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]interface{}{
			"id":              item.ID,
			"tenant_id":       item.TenantID,
			"device_id":       item.DeviceID,
			"slave_sae_id":    item.SlaveSAEID,
			"external_key_id": item.ExternalKeyID,
			"status":          item.Status,
			"qber":            round4(item.QBER),
			"key_size_bits":   item.KeySizeBits,
			"keycore_key_id":  item.KeyCoreKeyID,
			"created_at":      item.CreatedAt,
			"updated_at":      item.UpdatedAt,
			"injected_at":     item.InjectedAt,
		})
	}
	return out, nil
}

func (s *Service) ListLogs(ctx context.Context, tenantID string, limit int) ([]QKDLogEntry, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return nil, err
	}
	items, err := s.store.ListLogs(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func (s *Service) GenerateTestKeys(ctx context.Context, req TestGenerateRequest) (ReceiveKeysResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.SlaveSAEID = strings.TrimSpace(req.SlaveSAEID)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	req.Role = strings.TrimSpace(req.Role)
	req.LinkStatus = strings.TrimSpace(req.LinkStatus)
	if req.TenantID == "" || req.SlaveSAEID == "" {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and slave_sae_id are required")
	}
	if req.DeviceID == "" {
		req.DeviceID = "qkd-test-node"
	}
	if req.DeviceName == "" {
		req.DeviceName = req.DeviceID
	}
	if req.Role == "" {
		req.Role = "peer"
	}
	if req.LinkStatus == "" {
		req.LinkStatus = LinkStatusUp
	}
	if req.Count <= 0 {
		req.Count = 16
	}
	if req.Count > 500 {
		req.Count = 500
	}
	if req.KeySizeBits <= 0 {
		req.KeySizeBits = 256
	}
	if req.KeySizeBits%8 != 0 {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "key_size_bits must be divisible by 8")
	}
	if req.KeySizeBits < 128 || req.KeySizeBits > 4096 {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "key_size_bits must be between 128 and 4096")
	}
	if req.QBERMin < 0 || req.QBERMax < 0 || req.QBERMin > 1 || req.QBERMax > 1 {
		return ReceiveKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "qber range must be between 0 and 1")
	}
	if req.QBERMax < req.QBERMin {
		req.QBERMin, req.QBERMax = req.QBERMax, req.QBERMin
	}
	keyLen := req.KeySizeBits / 8
	keys := make([]ReceivedKey, 0, req.Count)
	for i := 0; i < req.Count; i++ {
		raw := make([]byte, keyLen)
		if _, err := pkgcrypto.Reader.Read(raw); err != nil {
			return ReceiveKeysResponse{}, newServiceError(http.StatusInternalServerError, "entropy_failed", err.Error())
		}
		qber := req.QBERMin
		if req.QBERMax > req.QBERMin {
			randV, err := secureRandUnitFloat64()
			if err != nil {
				return ReceiveKeysResponse{}, newServiceError(http.StatusInternalServerError, "entropy_failed", err.Error())
			}
			qber = req.QBERMin + (req.QBERMax-req.QBERMin)*randV
		}
		keys = append(keys, ReceivedKey{
			KeyID:       newID("qk"),
			MaterialB64: base64.StdEncoding.EncodeToString(raw),
			QBER:        round4(qber),
		})
		pkgcrypto.Zeroize(raw)
	}
	resp, err := s.ReceiveEncKeys(ctx, req.TenantID, req.SlaveSAEID, ReceiveKeysRequest{
		TenantID:   req.TenantID,
		DeviceID:   req.DeviceID,
		DeviceName: req.DeviceName,
		Role:       req.Role,
		LinkStatus: req.LinkStatus,
		Keys:       keys,
	})
	if err != nil {
		return ReceiveKeysResponse{}, err
	}
	_ = s.publishAudit(ctx, "audit.qkd.test_keys_generated", req.TenantID, map[string]interface{}{
		"slave_sae_id":  req.SlaveSAEID,
		"device_id":     req.DeviceID,
		"count":         req.Count,
		"key_size_bits": req.KeySizeBits,
		"accepted":      resp.AcceptedCount,
		"discarded":     resp.DiscardedCount,
	})
	s.log(ctx, req.TenantID, "test_generate", "info", "QKD test keys generated and ingested", map[string]interface{}{
		"slave_sae_id":  req.SlaveSAEID,
		"device_id":     req.DeviceID,
		"count":         req.Count,
		"key_size_bits": req.KeySizeBits,
		"qber_min":      req.QBERMin,
		"qber_max":      req.QBERMax,
		"accepted":      resp.AcceptedCount,
		"discarded":     resp.DiscardedCount,
	})
	return resp, nil
}

func (s *Service) InjectKey(ctx context.Context, keyID string, req InjectRequest) (InjectResponse, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	keyID = strings.TrimSpace(keyID)
	req.Name = strings.TrimSpace(req.Name)
	req.Purpose = strings.TrimSpace(req.Purpose)
	if req.TenantID == "" || keyID == "" {
		return InjectResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and key id are required")
	}
	cfg, err := s.GetConfig(ctx, req.TenantID)
	if err != nil {
		return InjectResponse{}, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return InjectResponse{}, err
	}
	key, err := s.store.GetKey(ctx, req.TenantID, keyID)
	if err != nil {
		return InjectResponse{}, err
	}
	if key.Status == KeyStatusDiscarded {
		return InjectResponse{}, newServiceError(http.StatusBadRequest, "key_discarded", "qkd key was discarded")
	}
	if key.Status == KeyStatusInjected && strings.TrimSpace(key.KeyCoreKeyID) != "" {
		return InjectResponse{
			QKDKeyID:     key.ID,
			KeyCoreKeyID: key.KeyCoreKeyID,
			Status:       "already_injected",
		}, nil
	}
	if s.keycore == nil {
		return InjectResponse{}, newServiceError(http.StatusFailedDependency, "keycore_unavailable", "keycore client is not configured")
	}
	raw, err := s.decryptKeyMaterial(key)
	if err != nil {
		return InjectResponse{}, err
	}
	defer pkgcrypto.Zeroize(raw)
	material := raw
	if len(material) != 32 {
		// Security: normalize arbitrary-length QKD material into deterministic AES-256 key bytes.
		material = hashToAES256(material)
		defer pkgcrypto.Zeroize(material)
	}
	materialB64 := base64.StdEncoding.EncodeToString(material)
	if req.Name == "" {
		req.Name = "qkd-" + key.ID
	}
	if req.Purpose == "" {
		req.Purpose = "encrypt"
	}
	keycoreKeyID, err := s.keycore.ImportAES256Key(ctx, req.TenantID, req.Name, req.Purpose, materialB64, map[string]string{
		"source":     "qkd",
		"qkd_key_id": key.ID,
		"device_id":  key.DeviceID,
	})
	if err != nil {
		return InjectResponse{}, newServiceError(http.StatusBadGateway, "keycore_import_failed", err.Error())
	}
	newStatus := KeyStatusInjected
	if req.Consume {
		newStatus = KeyStatusInjected
	}
	if err := s.store.SetKeyInjected(ctx, req.TenantID, key.ID, keycoreKeyID, newStatus); err != nil {
		return InjectResponse{}, err
	}
	_ = s.publishAudit(ctx, "audit.qkd.key_injected", req.TenantID, map[string]interface{}{
		"qkd_key_id":     key.ID,
		"keycore_key_id": keycoreKeyID,
		"device_id":      key.DeviceID,
		"slave_sae_id":   key.SlaveSAEID,
	})
	s.log(ctx, req.TenantID, "key_injected", "info", "QKD key injected into KeyCore", map[string]interface{}{
		"qkd_key_id":     key.ID,
		"keycore_key_id": keycoreKeyID,
		"device_id":      key.DeviceID,
		"slave_sae_id":   key.SlaveSAEID,
	})
	_ = s.checkPoolWarning(ctx, req.TenantID, key.SlaveSAEID, cfg)
	return InjectResponse{
		QKDKeyID:     key.ID,
		KeyCoreKeyID: keycoreKeyID,
		Status:       "injected",
	}, nil
}

func (s *Service) decryptKeyMaterial(k QKDKey) ([]byte, error) {
	return pkgcrypto.DecryptEnvelope(s.mek, &pkgcrypto.EnvelopeCiphertext{
		WrappedDEK:   k.WrappedDEK,
		WrappedDEKIV: k.WrappedDEKIV,
		Ciphertext:   k.Ciphertext,
		DataIV:       k.DataIV,
	})
}

func (s *Service) checkPoolWarning(ctx context.Context, tenantID string, slaveSAEID string, cfg QKDConfig) error {
	if cfg.PoolLowThreshold <= 0 {
		return nil
	}
	available, err := s.store.CountAvailableKeys(ctx, tenantID, slaveSAEID)
	if err != nil {
		return err
	}
	if available < cfg.PoolLowThreshold {
		_ = s.publishAudit(ctx, "audit.qkd.pool_low_warning", tenantID, map[string]interface{}{
			"slave_sae_id":   slaveSAEID,
			"available_keys": available,
			"low_threshold":  cfg.PoolLowThreshold,
		})
	}
	return nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "qkd",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func defaultExternalKeyID(v string, idx int) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return "ext-" + time.Now().UTC().Format("20060102150405") + "-" + strconvItoa(idx+1)
}

func round3(v float64) float64 {
	return math.Round(v*1000) / 1000
}

func round4(v float64) float64 {
	return math.Round(v*10000) / 10000
}

func secureRandUnitFloat64() (float64, error) {
	var b [8]byte
	if _, err := pkgcrypto.Reader.Read(b[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(b[:])
	return float64(v) / float64(^uint64(0)), nil
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ── Slave SAE Management ───────────────────────────────────

func (s *Service) RegisterSlaveSAE(ctx context.Context, req RegisterSAERequest) (SlaveSAE, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return SlaveSAE{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return SlaveSAE{}, newServiceError(http.StatusBadRequest, "bad_request", "name is required")
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = SAEModeETSI
	}
	role := strings.ToLower(strings.TrimSpace(req.Role))
	if role == "" {
		role = "consumer"
	}
	protocol := strings.TrimSpace(req.Protocol)
	if protocol == "" {
		protocol = "ETSI GS QKD 014"
	}
	qberT := req.QBERThreshold
	if qberT <= 0 || qberT > 1 {
		qberT = 0.11
	}
	now := time.Now().UTC()
	sae := SlaveSAE{
		ID:            newID("sae"),
		TenantID:      tenantID,
		Name:          name,
		Endpoint:      strings.TrimSpace(req.Endpoint),
		AuthToken:     strings.TrimSpace(req.AuthToken),
		Protocol:      protocol,
		Role:          role,
		Mode:          mode,
		Status:        SAEStatusActive,
		MaxKeyRate:    req.MaxKeyRate,
		QBERThreshold: qberT,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.store.CreateSlaveSAE(ctx, sae); err != nil {
		return SlaveSAE{}, err
	}
	s.log(ctx, tenantID, "sae_registered", "info", "slave SAE registered: "+sae.Name, map[string]interface{}{
		"sae_id": sae.ID, "mode": sae.Mode, "endpoint": sae.Endpoint,
	})
	_ = s.publishAudit(ctx, "audit.qkd.sae_registered", tenantID, map[string]interface{}{
		"sae_id": sae.ID, "name": sae.Name, "mode": sae.Mode, "role": sae.Role, "protocol": sae.Protocol,
	})
	sae.AuthToken = ""
	return sae, nil
}

func (s *Service) UpdateSlaveSAE(ctx context.Context, tenantID string, saeID string, req RegisterSAERequest) (SlaveSAE, error) {
	existing, err := s.store.GetSlaveSAE(ctx, tenantID, saeID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return SlaveSAE{}, newServiceError(http.StatusNotFound, "not_found", "slave SAE not found")
		}
		return SlaveSAE{}, err
	}
	if n := strings.TrimSpace(req.Name); n != "" {
		existing.Name = n
	}
	if e := strings.TrimSpace(req.Endpoint); e != "" {
		existing.Endpoint = e
	}
	if t := strings.TrimSpace(req.AuthToken); t != "" {
		existing.AuthToken = t
	}
	if p := strings.TrimSpace(req.Protocol); p != "" {
		existing.Protocol = p
	}
	if r := strings.TrimSpace(req.Role); r != "" {
		existing.Role = strings.ToLower(r)
	}
	if m := strings.TrimSpace(req.Mode); m != "" {
		existing.Mode = strings.ToLower(m)
	}
	if req.MaxKeyRate > 0 {
		existing.MaxKeyRate = req.MaxKeyRate
	}
	if req.QBERThreshold > 0 && req.QBERThreshold <= 1 {
		existing.QBERThreshold = req.QBERThreshold
	}
	existing.UpdatedAt = time.Now().UTC()
	if err := s.store.UpdateSlaveSAE(ctx, existing); err != nil {
		return SlaveSAE{}, err
	}
	s.log(ctx, tenantID, "sae_updated", "info", "slave SAE updated: "+existing.Name, map[string]interface{}{
		"sae_id": existing.ID,
	})
	_ = s.publishAudit(ctx, "audit.qkd.sae_updated", tenantID, map[string]interface{}{
		"sae_id": existing.ID, "name": existing.Name, "mode": existing.Mode, "role": existing.Role,
	})
	existing.AuthToken = ""
	return existing, nil
}

func (s *Service) ListSlaveSAEs(ctx context.Context, tenantID string) ([]SlaveSAE, error) {
	items, err := s.store.ListSlaveSAEs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []SlaveSAE{}
	}
	return items, nil
}

func (s *Service) GetSlaveSAE(ctx context.Context, tenantID string, id string) (SlaveSAE, error) {
	sae, err := s.store.GetSlaveSAE(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return SlaveSAE{}, newServiceError(http.StatusNotFound, "not_found", "slave SAE not found")
		}
		return SlaveSAE{}, err
	}
	sae.AuthToken = ""
	return sae, nil
}

func (s *Service) DeleteSlaveSAE(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteSlaveSAE(ctx, tenantID, id); err != nil {
		if errors.Is(err, errNotFound) {
			return newServiceError(http.StatusNotFound, "not_found", "slave SAE not found")
		}
		return err
	}
	s.log(ctx, tenantID, "sae_deleted", "info", "slave SAE deleted", map[string]interface{}{
		"sae_id": id,
	})
	_ = s.publishAudit(ctx, "audit.qkd.sae_deleted", tenantID, map[string]interface{}{"sae_id": id})
	return nil
}

func (s *Service) DistributeKeys(ctx context.Context, req DistributeKeysRequest) (DistributeKeysResponse, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return DistributeKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	saeID := strings.TrimSpace(req.SlaveSAEID)
	if saeID == "" {
		return DistributeKeysResponse{}, newServiceError(http.StatusBadRequest, "bad_request", "slave_sae_id is required")
	}
	count := req.Count
	if count <= 0 {
		count = 1
	}
	if count > 500 {
		count = 500
	}

	cfg, err := s.GetConfig(ctx, tenantID)
	if err != nil {
		return DistributeKeysResponse{}, err
	}
	if err := s.requireServiceEnabled(cfg); err != nil {
		return DistributeKeysResponse{}, err
	}

	sae, err := s.store.GetSlaveSAE(ctx, tenantID, saeID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return DistributeKeysResponse{}, newServiceError(http.StatusNotFound, "not_found", "slave SAE not found")
		}
		return DistributeKeysResponse{}, err
	}
	if sae.Status != SAEStatusActive {
		return DistributeKeysResponse{}, newServiceError(http.StatusConflict, "sae_inactive", "slave SAE is not active")
	}

	// Retrieve available keys from the pool for this tenant (any slave)
	keys, err := s.store.ListAvailableKeysBySlave(ctx, tenantID, "", count)
	if err != nil {
		return DistributeKeysResponse{}, err
	}
	if len(keys) == 0 {
		return DistributeKeysResponse{}, newServiceError(http.StatusConflict, "pool_empty", "no available keys in pool")
	}

	keyIDs := make([]string, len(keys))
	for i, k := range keys {
		keyIDs[i] = k.ID
	}

	// Mark keys as consumed
	if err := s.store.UpdateKeysStatus(ctx, tenantID, keyIDs, []string{KeyStatusAvailable}, KeyStatusConsumed); err != nil {
		return DistributeKeysResponse{}, err
	}

	distID := newID("dist")
	dist := Distribution{
		ID:            distID,
		TenantID:      tenantID,
		SlaveSAEID:    saeID,
		KeyCount:      len(keyIDs),
		KeySizeBits:   req.KeySizeBits,
		Status:        "completed",
		DistributedAt: time.Now().UTC(),
	}
	_ = s.store.CreateDistribution(ctx, dist)
	_ = s.store.IncrementSAEDistributed(ctx, tenantID, saeID, int64(len(keyIDs)))

	_ = s.publishAudit(ctx, "audit.qkd.keys_distributed", tenantID, map[string]interface{}{
		"distribution_id": distID,
		"sae_id":          saeID,
		"sae_name":        sae.Name,
		"key_count":       len(keyIDs),
	})
	s.log(ctx, tenantID, "keys_distributed", "info",
		"distributed "+strconvItoa(len(keyIDs))+" keys to "+sae.Name,
		map[string]interface{}{"sae_id": saeID, "distribution_id": distID, "key_count": len(keyIDs)})

	return DistributeKeysResponse{
		DistributionID: distID,
		SlaveSAEID:     saeID,
		KeyCount:       len(keyIDs),
		KeyIDs:         keyIDs,
		Status:         "completed",
	}, nil
}

func (s *Service) ListDistributions(ctx context.Context, tenantID string, slaveSAEID string, limit int) ([]Distribution, error) {
	items, err := s.store.ListDistributions(ctx, tenantID, slaveSAEID, limit)
	if err != nil {
		return nil, err
	}
	if items == nil {
		items = []Distribution{}
	}
	return items, nil
}
