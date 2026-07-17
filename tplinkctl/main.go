// Command tplinkctl logs in to a TP-Link router and runs encrypted API calls.
//
// Usage:
//
//	tplinkctl [flags] <path> [key=value ...]
//
// Examples:
//
//	export TPLINK_PASSWORD=secret
//	tplinkctl /admin/status?form=all operation=read
//	tplinkctl -host 192.168.0.1 /admin/wireless?form=guest operation=read
//
// The password is read from -password or the TPLINK_PASSWORD env var so it is
// never baked into the binary or shell history (use a leading space / env).

//go:debug rsa1024min=0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"golang.org/x/term"
)

func main() {
	host := flag.String("host", env("TPLINK_HOST", "192.168.0.1"), "router host/IP")
	user := flag.String("user", env("TPLINK_USERNAME", "admin"), "login username")
	pass := flag.String("password", os.Getenv("TPLINK_PASSWORD"), "admin password (or set TPLINK_PASSWORD)")
	rgSec := flag.Bool("rgsec", os.Getenv("TPLINK_RG_SEC") == "1", "use SHA-256 credential hash (RG-SEC regions)")
	force := flag.Bool("force", os.Getenv("TPLINK_FORCE") == "1", "force login, evicting any existing session (confirm=true)")
	flag.Parse()

	if *pass == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)  	
		}
		*pass = string(password)
	}

	args := flag.Args()
	if len(args) == 0 {
		// no path -> just prove login works and print the token
		args = []string{""}
	}
	path := args[0]

	fields := url.Values{}
	for _, kv := range args[1:] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "error: bad key=value %q\n", kv)
			os.Exit(2)
		}
		fields.Set(k, v)
	}
	if path != "" && len(fields) == 0 {
		fields.Set("operation", "read") // sensible default for reads
	}

	client := NewClient(Config{
		Host:     *host,
		Username: *user,
		Password: *pass,
		RGSec:    *rgSec,
		Force:    *force,
	})

	if err := client.Login(); err != nil {
		fmt.Fprintf(os.Stderr, "login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "login OK — stok=%s\n", client.Stok())

	if path == "" {
		return
	}

	data, err := client.Request(path, fields)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(prettyJSON(data))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func prettyJSON(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(out)
}
