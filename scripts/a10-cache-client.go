//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	forge "github.com/Sec-CH-Lemon/tls-forge"
	"github.com/Sec-CH-Lemon/tls-forge/profile"
	tc "github.com/igor-lemon/tls-client"
	"os"
	"time"
)

func main() {
	origin := flag.String("origin", "", "origin")
	scenarios := flag.String("scenarios", "", "scenarios")
	out := flag.String("out", "", "results")
	h3 := flag.Bool("h3", false, "race QUIC directly to the owned H3-only peer")
	selected := flag.String("profile", "", "explicit JSON profile; use client scope for a same-browser sequence")
	flag.Parse()
	raw, err := os.ReadFile(*scenarios)
	if err != nil {
		panic(err)
	}
	var cases []struct {
		ID string `json:"id"`
	}
	if err = json.Unmarshal(raw, &cases); err != nil {
		panic(err)
	}
	keys, err := os.OpenFile(*out+".keys", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	defer keys.Close()
	if *selected == "" {
		panic("an explicit -profile JSON is required")
	}
	p, err := profile.Get(*selected)
	if err != nil {
		panic(err)
	}
	opts := []forge.Option{forge.WithProfileValue(p), forge.WithInsecureSkipVerify(), forge.WithKeyLogWriter(keys)}
	if *h3 {
		opts = append(opts, forge.WithTransportOption(tc.WithProtocolRacing()))
	}
	client, err := forge.New(opts...)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	var rows []map[string]any
	for _, s := range cases {
		var responses []map[string]any
		for range 2 {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			r, e := client.Do(&forge.Request{URL: *origin + "/case/" + s.ID, Context: ctx, Browser: &forge.BrowserContext{Kind: forge.KindFetch, Initiator: *origin + "/start"}})
			cancel()
			if e != nil {
				panic(fmt.Sprintf("%s: %v", s.ID, e))
			}
			responses = append(responses, map[string]any{"status": r.Status, "body": string(r.Body)})
		}
		rows = append(rows, map[string]any{"id": s.ID, "api": responses})
	}
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(*out, b, 0600); err != nil {
		panic(err)
	}
}
