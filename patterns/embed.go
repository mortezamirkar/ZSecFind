// Package patterns embeds all regex pattern files used by the scanner.
package patterns

import "embed"

//go:embed categories secrets shared
var FS embed.FS
