// Command hive-relay is the open-source Hive relay binary: a content-blind
// rendezvous + envelope-forwarding server. It wires the default (open) behavior
// of the relay library; a downstream binary can import the same
// library and inject custom seams (see seams.go).
//
// Run the server (default):   hive-relay
// Generate an issuer keypair: hive-relay keygen
// Mint an entitlement token:  hive-relay issue --key <priv-hex> --sub <id> [...]
package main

import "github.com/honeyhive-ai/relay"

func main() { relay.Main() }
