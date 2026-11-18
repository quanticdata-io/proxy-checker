package checker_test

import (
	"context"
	"fmt"

	"github.com/quanticdata-io/proxy-checker/pkg/checker"
	"github.com/quanticdata-io/proxy-checker/pkg/proxy"
)

// Check one proxy five times and require a US exit.
func ExampleChecker_Check() {
	p, err := proxy.Parse("user:pass@gw.example.net:8080", proxy.HTTP)
	if err != nil {
		panic(err)
	}
	opts := checker.DefaultOptions()
	opts.Attempts = 5
	opts.ExpectCountry = "US"
	c, err := checker.New(opts)
	if err != nil {
		panic(err)
	}
	r := c.Check(context.Background(), p)
	fmt.Println(r.Pass, r.ExitIPs, r.Failures)
	if r.Latency != nil {
		fmt.Println("p50 ms:", r.Latency.P50)
	}
}

// Check a list concurrently and print the pool pass rate.
func ExampleChecker_Run() {
	list := []string{"203.0.113.7:3128", "socks5://user:pass@198.51.100.4:1080"}
	var ps []proxy.Proxy
	for _, s := range list {
		p, err := proxy.Parse(s, proxy.HTTP)
		if err != nil {
			panic(err)
		}
		ps = append(ps, p)
	}
	c, _ := checker.New(checker.DefaultOptions())
	results := c.Run(context.Background(), ps, nil)
	fmt.Printf("%.1f%% passed\n", checker.Summarise(results).PassRate)
}
