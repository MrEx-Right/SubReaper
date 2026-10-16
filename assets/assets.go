// Package assets embeds SubReaper's built-in data files into the binary, so
// they are available no matter where the tool is installed or run from.
package assets

import _ "embed"

// DefaultWordlist is the built-in subdomain wordlist, one label per line.
//
//go:embed wordlists/subdomains.txt
var DefaultWordlist []byte
