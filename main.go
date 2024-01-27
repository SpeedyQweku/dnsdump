package main

import (
	"strings"

	"github.com/gocolly/colly"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Blue   = "\033[34m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)


func getCsrfmiddlewaretoken(c *colly.Collector) string {
	var csrfmiddlewaretoken string
	c.OnHTML("input[name='csrfmiddlewaretoken']", func(h *colly.HTMLElement) {
		csrfmiddlewaretoken = h.Attr("value")
	})

	c.Visit("https://dnsdumpster.com/")

	return csrfmiddlewaretoken
}

func postTb(c *colly.Collector, csrfToken string, tagertip string) {
	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Headers.Set("Referer", "https://dnsdumpster.com/")
	})
	
	c.OnError(func(r *colly.Response, err error) {
		gologger.Error().Msgf("Error (POST):", err)
	})

	c.OnResponse(func(r *colly.Response) {
		gologger.Info().Msgf("Response received for POST %s\n", r.Request.URL)
		gologger.Info().Msgf("Status Code (POST): %v", r.StatusCode)

		c.OnHTML("div.col-md-12", func(b *colly.HTMLElement) {
			selection := b.DOM
			h4 := selection.Find("h4[style='color: #00CC00; text-align: left; font-size: 1.6em; line-height: 2.7em;']").Text()
			asn := selection.Find("p[style='text-align: left; font-size: 1.6em;']").Text()
			gologger.Print().Msg(Red+h4+Reset)
			gologger.Print().Msg(asn)
		})
		c.OnHTML("p[style='text-align: left; font-size: 1.6em; font-weight: 700;']", func(t *colly.HTMLElement) {
			gologger.Print().Msg(t.Text)
		})
		c.OnHTML("p[style=\"margin-top: 40px; color: #ddd; font-family: 'Courier New', Courier, monospace; text-align: left;\"]", func(b *colly.HTMLElement) {
			gologger.Print().Msg(Red+b.Text+Reset)
		})

		c.OnHTML("div.table-responsive > table.table > tbody > tr", func(t *colly.HTMLElement) {
			ip := t.ChildText("td.col-md-3")
			gologger.Print().Msg(Yellow+ip+Reset)
		})
		c.OnHTML("div.table-responsive > table.table > tbody > tr > td > span", func(t *colly.HTMLElement) {
			fields := strings.TrimSpace(t.Text)
			gologger.Print().Msgf(Cyan+fields+Reset)
		})
	})

	
	postData := map[string]string{
		"csrfmiddlewaretoken": csrfToken,
		"targetip":            tagertip,
		"user":                "free",
	}

	c.Post("https://dnsdumpster.com/", postData)
}

var targetip string
func main() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("dnsdump, dump result from dnsdumpster")
	flagSet.CreateGroup("input", "INPUT",
		flagSet.StringVar(&targetip,"ip","","Target Ip"),
	)
	_ = flagSet.Parse()
	if targetip != "" {
		c := colly.NewCollector(colly.AllowedDomains("dnsdumpster.com"))
		csrfmiddlewareToken := getCsrfmiddlewaretoken(c)
		postTb(c, csrfmiddlewareToken, targetip)
	}else{
		gologger.Fatal().Msg("Please specify a target ip using -ip/--ip")
	}
}
