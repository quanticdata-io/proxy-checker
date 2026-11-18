// Command locallab starts a local test lab on 127.0.0.1 so you can try
// proxy-checker without any real proxy and without leaving your machine:
//
//	:18081  IP echo (/ip, /flat, /text, /headers, /page, /status/N)
//	:18080  HTTP proxy, user "demo" password "demo", rotating exit IP per request
//	:18083  HTTP proxy, no auth, sticky exit IP, exit country DE, adds a Via header
//	:18082  SOCKS4/SOCKS5 proxy, SOCKS5 user "demo" password "demo"
//
// Run it with `go run ./examples/locallab` and press Ctrl+C to stop.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/quanticdata-io/proxy-checker/internal/testutil"
)

func serve(addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("%s: %v", addr, err)
		}
	}()
}

func main() {
	serve("127.0.0.1:18081", testutil.EchoHandler())
	serve("127.0.0.1:18080", &testutil.HTTPProxy{Username: "demo", Password: "demo", Exit: testutil.ExitRotating, Country: "US"})
	serve("127.0.0.1:18083", &testutil.HTTPProxy{Exit: testutil.ExitSticky, Country: "DE", AddHeaders: map[string]string{"Via": "1.1 locallab"}})
	socks, err := testutil.ListenSOCKS("127.0.0.1:18082", "demo", "demo")
	if err != nil {
		log.Fatal(err)
	}
	defer socks.Close()

	fmt.Println(`local lab is running. Try:

  proxy-checker --echo-url http://127.0.0.1:18081/ip demo:demo@127.0.0.1:18080 127.0.0.1:18083 socks5://demo:demo@127.0.0.1:18082
  proxy-checker --echo-url http://127.0.0.1:18081/ip -n 5 --expect-rotation demo:demo@127.0.0.1:18080
  proxy-checker --echo-url http://127.0.0.1:18081/ip -n 5 --expect-sticky --expect-country DE 127.0.0.1:18083
  proxy-checker --echo-url http://127.0.0.1:18081/ip --headers-url http://127.0.0.1:18081/headers 127.0.0.1:18083

Press Ctrl+C to stop.`)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
