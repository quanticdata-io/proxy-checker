package checker

import (
	"math"
	"sort"
)

// percentile returns the nearest-rank percentile (0 < p <= 100) of sorted values.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

func summarise(tries []Attempt) *Latency {
	var total, connect, ttfb []float64
	for _, a := range tries {
		if !a.OK {
			continue
		}
		total = append(total, a.TotalMs)
		if a.ConnectMs > 0 {
			connect = append(connect, a.ConnectMs)
		}
		if a.TTFBMs > 0 {
			ttfb = append(ttfb, a.TTFBMs)
		}
	}
	if len(total) == 0 {
		return nil
	}
	sort.Float64s(total)
	return &Latency{
		Min:        round1(total[0]),
		P50:        round1(percentile(total, 50)),
		P95:        round1(percentile(total, 95)),
		Max:        round1(total[len(total)-1]),
		ConnectAvg: round1(mean(connect)),
		TTFBAvg:    round1(mean(ttfb)),
	}
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

// Summary aggregates a run.
type Summary struct {
	Total     int            `json:"total"`
	Passed    int            `json:"passed"`
	Failed    int            `json:"failed"`
	PassRate  float64        `json:"pass_rate"`
	UniqueIPs int            `json:"unique_exit_ips"`
	MedianP50 float64        `json:"median_p50_ms"`
	ByCountry map[string]int `json:"by_country,omitempty"`
}

// Summarise aggregates results.
func Summarise(results []Result) Summary {
	s := Summary{Total: len(results), ByCountry: map[string]int{}}
	ips := map[string]bool{}
	var p50 []float64
	for _, r := range results {
		if r.Pass {
			s.Passed++
		}
		for _, ip := range r.ExitIPs {
			ips[ip] = true
		}
		if r.Latency != nil {
			p50 = append(p50, r.Latency.P50)
		}
		if r.Geo != nil && r.Geo.CountryCode != "" && r.Successes > 0 {
			s.ByCountry[r.Geo.CountryCode]++
		}
	}
	s.Failed = s.Total - s.Passed
	if s.Total > 0 {
		s.PassRate = round1(float64(s.Passed) / float64(s.Total) * 100)
	}
	s.UniqueIPs = len(ips)
	sort.Float64s(p50)
	s.MedianP50 = round1(percentile(p50, 50))
	if len(s.ByCountry) == 0 {
		s.ByCountry = nil
	}
	return s
}
