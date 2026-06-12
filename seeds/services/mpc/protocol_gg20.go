package main

import (
	"sort"
	"strings"
)

func combineGG20Partials(messageHash string, partials map[string]string) string {
	keys := make([]string, 0, len(partials))
	for k := range partials {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{"gg20", strings.TrimSpace(messageHash)}
	for _, k := range keys {
		parts = append(parts, k, strings.TrimSpace(partials[k]))
	}
	return sha256Hex(parts...)
}
