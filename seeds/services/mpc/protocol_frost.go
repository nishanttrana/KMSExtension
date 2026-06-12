package main

import (
	"sort"
	"strings"
)

func combineFROSTPartials(messageHash string, partials map[string]string) string {
	keys := make([]string, 0, len(partials))
	for k := range partials {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{"frost", strings.TrimSpace(messageHash)}
	for _, k := range keys {
		parts = append(parts, k, strings.TrimSpace(partials[k]))
	}
	return sha256Hex(parts...)
}
