package app

import (
	"flag"
	"strings"
)

// parseCLI splits flags and scan targets so flags may appear before or after paths.
func parseCLI(fs *flag.FlagSet, args []string) ([]string, error) {
	var flags []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			flags = append(flags, arg)
			continue
		}
		flags = append(flags, arg)
		if needsFlagValue(name) && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			flags = append(flags, args[i])
		}
	}

	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}

func needsFlagValue(name string) bool {
	switch name {
	case "version", "safe", "no-crawl", "fail-on-find", "only-secrets", "q":
		return false
	default:
		return true
	}
}
