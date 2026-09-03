package adapters

import (
	"fmt"
	"strings"
)

// Deny workload primitives that would grant host control beyond ordinary deployment rights.
func validateWorkload(v any) error {
	switch x := v.(type) {
	case map[string]any:
		for key, value := range x {
			k := strings.ToLower(key)
			switch k {
			case "privileged", "hostpid", "hostipc", "hostnetwork", "allowprivilegeescalation":
				if value == true || value == "true" {
					return fmt.Errorf("privileged workload field %s is forbidden", key)
				}
			case "hostpath", "devices", "cap_add":
				if value != nil {
					return fmt.Errorf("host access field %s is forbidden", key)
				}
			case "network_mode", "pid", "ipc":
				if value == "host" {
					return fmt.Errorf("host namespace forbidden")
				}
			case "driver":
				if driver, ok := value.(string); ok && driver != "docker" && driver != "podman" {
					return fmt.Errorf("Nomad driver must be docker or podman")
				}
			case "capabilities":
				if m, ok := value.(map[string]any); ok && m["add"] != nil {
					return fmt.Errorf("added capabilities forbidden")
				}
			case "volumes":
				if values, ok := value.([]any); ok {
					for _, vol := range values {
						if raw, ok := vol.(string); ok && (strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".")) {
							return fmt.Errorf("host volume binding forbidden")
						}
					}
				}
			case "type":
				if value == "bind" {
					return fmt.Errorf("host bind mounts forbidden")
				}
			}
			if e := validateWorkload(value); e != nil {
				return e
			}
		}
	case []any:
		for _, item := range x {
			if e := validateWorkload(item); e != nil {
				return e
			}
		}
	}
	return nil
}
