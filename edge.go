package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

/* Global Variables */
var prefixes Prefixes
var prefixesv6 Prefixesv6
var values Values
var gprefixes GPrefixes
var cfprefixes CFPrefixes
var doprefixes DOPrefixes
var csvfile *os.File
var error_timeout = 0
var dns_lookups = 0
var records_found = 0
var edge_version = "0.2.4"
var (
	flDomain      = flag.String("domain", "", "The domain to perform guessing against.")
	flWordlist    = flag.String("wordlist", "", "The wordlist to use for guessing.")
	flCsv         = flag.String("csv", "", "Output results to CSV file")
	flServerAddr  = flag.String("resolver", "8.8.8.8:53", "The DNS server to use.")
	flIp          = flag.String("ip", "", "The text file to use with IP addresses")
	flNmap        = flag.String("nmap", "", "Nmap scan xml file to use.")
	flWorkerCount = flag.Int("workers", 10, "The amount of workers to use.")
	flSingle      = flag.String("single", "", "Single IP address to do a prefix lookup")
	ptrFlag       = false
	prefixFlag    = false
	crtFlag       = false
	dnsFlag       = false
	verboseFlag   = false
	outputFlag    = false
	silentFlag    = false
	azurejson     = "azure.json"
	azureurl      = "https://azservicetags.azurewebsites.net/"
	googlejson    = "cloud.json"
	googleurl     = "https://www.gstatic.com/ipranges/cloud.json"
	awsjson       = "aws.json"
	awsurl        = "https://ip-ranges.amazonaws.com/ip-ranges.json"
	cfipv4txt     = "cloudflare-ipv4.txt"
	cfipv4url     = "https://www.cloudflare.com/ips-v4/#"
	cfipv6txt     = "cloudflare-ipv6.txt"
	cfipv6url     = "https://www.cloudflare.com/ips-v6/#"
	docsv         = "digitalocean.csv"
	dourl         = "https://digitalocean.com/geo/google.csv"
)

func DownloadFile(filepath string, url string) error {

	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[ERR] Failed to download the file: %s. Error: %v\n", filepath, err)
		return err
	}
	defer resp.Body.Close()

	// Check if the HTTP request was successful
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("[ERR] failed to download from url: %s. Server returned status code: %d", url, resp.StatusCode)
		fmt.Println(err)
		fmt.Println("[ERR] Are you offline?")
		fmt.Println("[ERR] Try coping the missing file from 'csp-files' directory to working directory")
		os.Exit(1)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	fmt.Printf("[INF] File %s has been downloaded and created\n", filepath)

	_, err = io.Copy(out, resp.Body)
	return err
}

func fwd_dns_request(query string, serverAddr string) []result {

	var results []result
	var fqdn = strings.TrimSuffix(query, ".")
	var source = "A"
	var cname_response = ""
	var pdesc = ""
	dns_lookups++

	var m dns.Msg
	m.SetQuestion(dns.Fqdn(query), dns.TypeA)
	in, err := dns.Exchange(&m, serverAddr)

	if isFlagPassed("verbose") {
		fmt.Println("[+] Looking up", fqdn)
	}

	if err != nil {
		error_timeout++
		if isFlagPassed("verbose") {
			fmt.Println("Error:", err)
		}
		return nil
	}

	if in.MsgHdr.Rcode == 3 {
		// No such name result - don't process any further
		return nil
	}
	if len(in.Answer) == 0 {
		// Answer length is 0 - don't process any further
		return nil
	}

	if a, ok := in.Answer[0].(*dns.A); ok {

		// increment records found

		ip_addr := a.A.String()

		if isFlagPassed("prefix") {
			if retval1, desc := prefixes.aws_lookup(ip_addr); retval1 {
				pdesc = desc
			} else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
				pdesc = desc2
			} else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
				pdesc = desc3
			} else if retval4, desc4 := cfprefixes.cf_lookup(ip_addr); retval4 {
				pdesc = desc4
			} else if retval5, desc5 := doprefixes.do_lookup(ip_addr); retval5 {
				pdesc = desc5
			} else {
				pdesc = ""
			}
			results = append(results, result{IPAddress: a.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})
		}

		results = append(results, result{IPAddress: ip_addr, Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})

	} else if a, ok := in.Answer[0].(*dns.CNAME); ok {
		source = "CNAME"
		for _, s := range in.Answer {

			// increment records found
			//records_found++

			if cresp, ok := s.(*dns.A); ok {
				cname_response = strings.TrimSuffix(a.Target, ".")
				source = "A"

				ip_addr := cresp.A.String()

				if isFlagPassed("prefix") {
					if retval1, desc := prefixes.aws_lookup(ip_addr); retval1 {
						pdesc = desc
					} else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
						pdesc = desc2
					} else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
						pdesc = desc3
					} else if retval4, desc4 := cfprefixes.cf_lookup(ip_addr); retval4 {
						pdesc = desc4
					} else if retval5, desc5 := doprefixes.do_lookup(ip_addr); retval5 {
						pdesc = desc5
					} else {
						pdesc = ""
					}
					results = append(results, result{IPAddress: cresp.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})
				}

				results = append(results, result{IPAddress: cresp.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})

			} else if cresp, ok := s.(*dns.CNAME); ok {
				source = "CNAME"
				hostname := cresp.Header().Name
				fqdn = strings.TrimSuffix(cresp.Target, ".")
				results = append(results, result{IPAddress: "", Hostname: hostname, Source: source, CNAME_Response: fqdn, Description: pdesc})
				fwd_dns_request(fqdn, serverAddr)
			} else {

			}

		}

	}

	return results
}

func worker(tracker chan empty, fqdns chan string, gather chan []result, serverAddr string) {
	for fqdn := range fqdns {
		lookup := fqdn + "."
		results := fwd_dns_request(lookup, serverAddr)
		if len(results) > 0 {
			gather <- results
		}
	}
	var e empty
	tracker <- e

}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func crt_transparency(domain_string string, serverAddr string) []result {

	var results []result

	query_string := "https://crt.sh?q=" + domain_string
	resp, err := http.Get(query_string)

	if err != nil {
		log.Fatalln(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	// Convert the body to type string
	sb := string(body)

	body2 := strings.NewReader(sb)

	z := html.NewTokenizer(body2)
	content := []string{}

	// While have not hit the </html> tag
	for z.Token().Data != "html" {
		tt := z.Next()
		if tt == html.StartTagToken {
			t := z.Token()
			if t.Data == "td" {
				inner := z.Next()
				if inner == html.TextToken {
					text := (string)(z.Text())
					t := strings.TrimSpace(text)
					content = append(content, t)
				}
			}
		}
	}

	content2 := removeDuplicateStr(content)

	sum := 0
	for _, v := range content2 {
		if strings.Contains(v, domain_string) && !strings.HasPrefix(v, "*.") {

			if strings.Contains(v, "Type: Identity") {
				// Remove the first line
			} else {

				results = append(results, result{IPAddress: "", Hostname: v, Source: "Certificate", CNAME_Response: ""})
				sum += 1

				if isFlagPassed("dns") {

					// Write the csv file
					x := csv.NewWriter(csvfile)
					defer x.Flush()

					lookup := v + "."
					result := fwd_dns_request(lookup, serverAddr)

					w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
					for _, r := range result {
						// Print summary [INF]
						if silentFlag == false {
							if r.Source == "A" {
								s := fmt.Sprintf("[INF] Found host via A [%s:%s]", r.Hostname, r.IPAddress)
								fmt.Println(s)
							} else if r.Source == "CNAME" {
								s := fmt.Sprintf("[INF] Found host via CNAME [%s:%s]", r.Hostname, r.CNAME_Response)
								fmt.Println(s)
							}

							//parse and print r.Description if not empty
							//which means a cloud provider prefix has been matched
							if r.Description == "" {
								//empty string, didn't match to a cloud provider
							} else {

								desc_elements := strings.Split(r.Description, ";")
								provider := desc_elements[0]
								provider_elements := strings.Split(provider, ":")
								csp := provider_elements[1]
								prefix := desc_elements[1]
								prefix_elements := strings.Split(prefix, ":")
								csp_prefix := prefix_elements[1]

								s := fmt.Sprintf("[INF] Matched Cloud Provider via prefix [%s:%s]", csp, csp_prefix)
								fmt.Println(s)

								// Extract the service if AWS or Azure, extract the region if GCP
								if csp == "AWS" || csp == "Azure" || csp == "GCP" {
									service_string := ""
									region_string := ""
									csp_region := ""
									s := ""
									if csp == "AWS" {
										service_string = desc_elements[3]
										region_string = desc_elements[2]
										regions := strings.Split(region_string, ":")
										csp_region = regions[1]
										services := strings.Split(service_string, ":")
										csp_svc := services[1]
										s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s] and Region [%s]", r.IPAddress, csp_svc, csp_region)
									} else if csp == "Azure" {
										//Parse azure description for SystemService
										service_string = desc_elements[5]
										services := strings.Split(service_string, ":")
										csp_svc := services[1]
										s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s]", r.IPAddress, csp_svc)
									} else if csp == "GCP" {
										region_string = desc_elements[2]
										regions := strings.Split(region_string, ":")
										csp_region = regions[1]
										s = fmt.Sprintf("[INF] Matched IP [%s] to Region [%s]", r.IPAddress, csp_region)
									}
									fmt.Println(s)

								}
							}

						}

						// print detailed line
						fmt.Fprintf(w, "%s,%s,%s,%s,%s\n", r.Hostname, r.IPAddress, r.Source, r.CNAME_Response, r.Description)

						if isFlagPassed("output") {
							record := []string{r.Hostname, r.IPAddress, r.Source, r.CNAME_Response, r.Description}
							if err := x.Write(record); err != nil {
								log.Fatalln("Error writing record to file:", err)
							}
						}
					}
					w.Flush()

				}
			}
		}
	}
	return results

}

type empty struct{}

type result struct {
	IPAddress      string
	Hostname       string
	Source         string
	CNAME_Response string
	Description    string
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func reverse(lookup string) string {
	ptr, _ := net.LookupAddr(lookup)

	dns_lookups++
	if len(ptr) > 0 {
		for _, ptrvalue := range ptr {
			return ptrvalue
		}
	}
	return ""
}

func (s *GPrefixes) gcloud_lookup(lookup string) (bool, string) {

	var description = ""

	for i := 0; i < len(s.GPrefixes); i++ {
		IPAddress := net.ParseIP(lookup)
		if s.GPrefixes[i].Ipv4prefix != "" {
			_, ipv4Net, _ := net.ParseCIDR(s.GPrefixes[i].Ipv4prefix)
			mybool := ipv4Net.Contains(IPAddress)
			if mybool == true {
				description := fmt.Sprintf("Provider:GCP;Prefix:%s;Region:%s", s.GPrefixes[i].Ipv4prefix, s.GPrefixes[i].Scope)
				if isFlagPassed("verbose") {
					fmt.Println("    [+] Found Google Cloud prefix:", s.GPrefixes[i].Ipv4prefix)
				}
				return true, description
			}

		} else if s.GPrefixes[i].Ipv6prefix != "" {
			// Ipv6, so do nothing

		}
	}
	return false, description
}

func (s *DOPrefixes) do_lookup(lookup string) (bool, string) {
	var description = ""

	IPAddress := net.ParseIP(lookup)
	if IPAddress == nil {
		return false, "[ERR] Invalid IP address format"
	}

	for _, prefix := range s.DOPrefixes {
		if prefix.Prefix != "" {
			_, ipv4Net, _ := net.ParseCIDR(prefix.Prefix)
			if ipv4Net.Contains(IPAddress) {
				description := fmt.Sprintf("Provider:DigitalOcean;Prefix:%s;Country:%s;State:%s;City:%s;ASN:%s",
					prefix.Prefix, prefix.Country, prefix.State, prefix.City, prefix.ASN)
				// fmt.Println("    [+] Found DigitalOcean prefix:", prefix.Prefix)
				return true, description
			}
		}
	}
	return false, description
}

func (s *CFPrefixes) cf_lookup(lookup string) (bool, string) {

	var description = ""

	IPAddress := net.ParseIP(lookup)
	if IPAddress == nil {
		return false, "[ERR] Invalid IP address format"
	}

	for i := 0; i < len(s.CFPrefixes); i++ {

		if s.CFPrefixes[i].Prefix != "" {
			_, ipv4Net, _ := net.ParseCIDR(s.CFPrefixes[i].Prefix)
			mybool := ipv4Net.Contains(IPAddress)
			if mybool == true {
				description := fmt.Sprintf("Provider:Cloudflare;Prefix:%s", s.CFPrefixes[i].Prefix)
				if isFlagPassed("verbose") {
					fmt.Println("    [+] Found Cloudflare prefix:", s.CFPrefixes[i].Prefix)
				}
				return true, description
			}
		}
	}
	return false, description
}

func (s *Prefixes) aws_lookup(lookup string) (bool, string) {

	/* In aws prefixes, an IP address can match more than one prefix
	   find all matches prefixes and return the longest prefix match
	   this will show the more detailed service instead of a supernet netblock
	*/

	var description = ""

	// structure for holding longest prefix match
	type Blob struct {
		prefix  string
		region  string
		service string
	}

	// there should not be more than 2 or 3 prefix matches, but specifying 10 just to be safe
	mprefixes := make([]Blob, 10)
	mindex := 0
	atleastonematch := false
	for i := 0; i < len(s.Prefixes); i++ {
		IPAddress := net.ParseIP(lookup)
		_, ipv4Net, _ := net.ParseCIDR(s.Prefixes[i].Ip_prefix)
		mybool := ipv4Net.Contains(IPAddress)
		if mybool == true {
			tmpStruct := Blob{
				prefix:  s.Prefixes[i].Ip_prefix,
				region:  s.Prefixes[i].Region,
				service: s.Prefixes[i].Service,
			}

			// Skip if the service name is 'AMAZON' as this doesn't tell us anything new
			if s.Prefixes[i].Service != "AMAZON" {
				mprefixes[mindex] = tmpStruct
			}

			mindex++
			atleastonematch = true
		}
	}
	// Store the longest prefix match into variable
	longestprefix := ""
	longestregion := ""
	longestservice := ""

	if atleastonematch == true {

		// iterate through all of the prefix matches and find longest one
		for _, mprefixes := range mprefixes {
			if mprefixes.prefix == "" {

			} else {
				// if first element in slice, add it
				if longestprefix == "" {
					longestprefix = mprefixes.prefix
					longestregion = mprefixes.region
					longestservice = mprefixes.service
				} else {
					// get the prefix from prefixes
					// split the string based on /
					elements1 := strings.Split(mprefixes.prefix, "/")
					prefix1 := elements1[1]
					intprefix1, _ := strconv.Atoi(prefix1)

					// extract prefix from longestprefix variable
					elements2 := strings.Split(longestprefix, "/")
					prefix2 := elements2[1]
					intprefix2, _ := strconv.Atoi(prefix2)

					if intprefix1 > intprefix2 {
						longestprefix = mprefixes.prefix
						longestregion = mprefixes.region
						longestservice = mprefixes.service

					}
				}
			}
		}

		description := fmt.Sprintf("Provider:AWS;Prefix:%s;Region:%s;Service:%s", longestprefix, longestregion, longestservice)
		return true, description
	}
	return false, description
}

func (s *Values) azure_lookup(lookup string) (bool, string) {
	IPAddress := net.ParseIP(lookup)

	var description = ""

	for z := 0; z < len(s.Values); z++ {
		for i := 0; i < len(s.Values[z].Properties.Addressprefixes); i++ {

			_, ipv4Net, _ := net.ParseCIDR(s.Values[z].Properties.Addressprefixes[i])
			mybool := ipv4Net.Contains(IPAddress)
			if mybool == true {

				description := fmt.Sprintf("Provider:Azure;Prefix:%s;Name:%s;ID:%s;Platform:%s;SystemService:%s", s.Values[z].Properties.Addressprefixes[i], s.Values[z].Name, s.Values[z].Id, s.Values[z].Properties.Platform, s.Values[z].Properties.Systemservice)
				if isFlagPassed("verbose") {
					fmt.Println("[VERBOSE] Found Azure prefix:", s.Values[z].Properties.Addressprefixes[i])
					fmt.Println("[VERBOSE] Name:", s.Values[z].Name)
					fmt.Println("[VERBOSE] ID:", s.Values[z].Id)
					fmt.Println("[VERBOSE] Platform:", s.Values[z].Properties.Platform)
					fmt.Println("[VERBOSE] SystemService:", s.Values[z].Properties.Systemservice)
				}
				return true, description
			}

		}
	}

	return false, description

}

func getAzureJSONURL(baseURL string) (string, error) {
	resp, err := http.Get(baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	tokenizer := html.NewTokenizer(resp.Body)
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case html.ErrorToken:
			err := tokenizer.Err()
			if err == io.EOF {
				return "", fmt.Errorf("[ERR] Azure JSON URL not found")
			}
			return "", err
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "a" {
				for _, attr := range token.Attr {
					if attr.Key == "href" && strings.Contains(attr.Val, "Public") {
						return attr.Val, nil
					}
				}
			}
		}
	}
}

func checkCSPFiles() {

	// Parse and retrieve the dynamically changing json endpoint for Azure
	azureURL, err := getAzureJSONURL(azureurl)
	if err != nil {
		panic(err)
	}

	files := map[string]string{
		azurejson:  azureURL,
		googlejson: googleurl,
		awsjson:    awsurl,
		cfipv4txt:  cfipv4url,
		cfipv6txt:  cfipv6url,
		docsv:      dourl,
	}

	for filename, url := range files {
		_, err := os.Stat(filename)
		if os.IsNotExist(err) {
			err := DownloadFile(filename, url)
			if err != nil {
				panic(err)
			}
		}
	}
}

func loadDOPrefixes(filePath string) (DOPrefixes, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return DOPrefixes{}, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	var doPrefixes DOPrefixes
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return DOPrefixes{}, err
		}

		if len(record) < 5 {
			fmt.Println("Invalid record:", record)
			continue
		}

		doPrefix := DOPrefix{
			Prefix:  record[0],
			Country: record[1],
			State:   record[2],
			City:    record[3],
			ASN:     record[4],
		}
		doPrefixes.DOPrefixes = append(doPrefixes.DOPrefixes, doPrefix)
	}

	return doPrefixes, nil
}

func loadCFPrefixes(filePath string) (CFPrefixes, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return CFPrefixes{}, err
	}
	defer file.Close()

	var cfIPv4Prefixes CFPrefixes
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipv4Prefix := scanner.Text()
		cfIPv4Prefix := CFPrefix{Prefix: ipv4Prefix}
		cfIPv4Prefixes.CFPrefixes = append(cfIPv4Prefixes.CFPrefixes, cfIPv4Prefix)
	}

	if err := scanner.Err(); err != nil {
		return CFPrefixes{}, err
	}

	return cfIPv4Prefixes, nil
}

// Nmap structures
type Nmaprun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Hosts  `xml:"host"`
}

type Hosts struct {
	XMLName xml.Name `xml:"host"`
	Status  Status   `xml:"status"`
	Address Address  `xml:"address"`
}

type Status struct {
	XMLName xml.Name `xml:"status"`
	State   string   `xml:"state,attr"`
}

type Address struct {
	XMLName xml.Name `xml:"address"`
	Addr    string   `xml:"addr,attr"`
}

// End of Nmap structures

// Start of Cloudflare Structures
type CFPrefixes struct {
	CFPrefixes []CFPrefix
}

type CFPrefix struct {
	Prefix string
}

// End of Cloudflare Structures

// Digital Ocean strusture
type DOPrefixes struct {
	DOPrefixes []DOPrefix
}

type DOPrefix struct {
	Prefix  string
	Country string
	State   string
	City    string
	ASN     string
}

// Start of AWS Structures
type Prefixes struct {
	Prefixes []Prefix `json:"prefixes"`
}

type Prefixesv6 struct {
	Prefixesv6 []Prefixv6 `json:"ipv6_prefixes"`
}

type Prefix struct {
	Ip_prefix string `json:"ip_prefix"`
	Region    string `json:"region"`
	Service   string `json:"service"`
	NBG       string `json:"network_border_group"`
}

type Prefixv6 struct {
	Ipv6_prefix string `json:"ipv6_prefix"`
	Region      string `json:"region"`
	Service     string `json:"service"`
	NBG         string `json:"network_border_group"`
}

// End of AWS Structures

// Start of Azure Structures
type Values struct {
	Values []Value `json:"values"`
}

type Value struct {
	Name       string     `json:"name"`
	Id         string     `json:"id"`
	Properties Properties `json:"properties"`
}

type Properties struct {
	Changenumber    string   `json:"changeNumber"`
	Region          string   `json:"region"`
	Regionid        string   `json:"regionId"`
	Platform        string   `json:"platform"`
	Systemservice   string   `json:"systemService"`
	Addressprefixes []string `json:"addressPrefixes"`
	Networkfeatures []string `json:"networkFeatures"`
}

// End of Azure Structures

// Start of Gcloud Structures
type GPrefixes struct {
	GPrefixes []GPrefix `json:"prefixes"`
}

type GPrefix struct {
	Ipv4prefix string `json:"ipv4Prefix"`
	Ipv6prefix string `json:"ipv6Prefix"`
	Scope      string `json:"scope"`
}

// End of Gcloud Structures

func main() {

	start := time.Now()

	flag.BoolVar(&ptrFlag, "ptr", false, "PTR lookup mode")
	flag.BoolVar(&prefixFlag, "prefix", false, "IP Prefix CSP lookup mode")
	flag.BoolVar(&crtFlag, "crt", false, "Certificate transparency lookup mode")
	flag.BoolVar(&dnsFlag, "dns", false, "A and CNAME record lookup mode")
	flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
	flag.BoolVar(&outputFlag, "output", false, "Enable output to CSV")
	flag.BoolVar(&silentFlag, "silent", false, "Enable silent mode to suppress [INF]")

	flag.Parse()

	// Start
	if silentFlag == false {
		version_line := fmt.Sprintf("[INF] Starting Cloud Edge version %s", edge_version)
		fmt.Println(version_line)
	}

	// Check all the CSP files (json, csv, txt)
	checkCSPFiles()

	if *flDomain == "" && *flIp == "" && *flNmap == "" && *flSingle == "" {
		fmt.Println("[WRN] -domain or -ip or -nmap or -single mode is required")
		fmt.Println("[WRN] Example 1:  -domain acme.com")
		fmt.Println("[WRN] Example 2:  -ip hosts.txt -ptr")
		fmt.Println("[WRN] Example 3:  -ip hosts.txt -prefix")
		fmt.Println("[WRN] Example 4:  -single <ip_addr>")
		os.Exit(1)
	}

	if *flDomain != "" {
		if !isFlagPassed("crt") && !isFlagPassed("dns") {
			fmt.Println("[WRN] Either -crt or -dns mode must be specified with -domain <domain>")
			fmt.Println("[WRN] Example 1:  -domain acme.com -dns")
			fmt.Println("[WRN] Example 2:  -domain acme.com -crt")
			os.Exit(1)
		}
	}

	if *flIp != "" && *flNmap != "" {
		fmt.Println("[WRN] Please select either -ip or -nmap when using reverse lookup mode")
		fmt.Println("[WRN] Example 1:  -domain acme.com -dns")
		os.Exit(1)
	}

	// Check if ip address list is specified
	if *flIp == "" {
	} else {
		if isFlagPassed("crt") {
			fmt.Println("[WRN] The IP address mode (-ip) can't be enabled with -crt mode")
			os.Exit(1)
		} else if isFlagPassed("dns") {
			fmt.Println("[WRN] The IP address mode (-ip) can't be enabled with -dns mode")
			os.Exit(1)
		}

		if isFlagPassed("ptr") || isFlagPassed("prefix") {
		} else {
			fmt.Println("[WRN] Please select either -ptr or -prefix when specifying an IP address list (-ip)")
			os.Exit(1)
		}
	}

	// For now only allow -prefix or -ptr:  Not both
	if isFlagPassed("ptr") && isFlagPassed("prefix") {
		fmt.Println("[WRN] Please specify either PTR mode (-ptr) or Prefix mode (-prefix)")
		fmt.Println("[WRN] Both flags are set and this is not allowed")
		os.Exit(1)
	}

	if isFlagPassed("output") {
		if *flCsv == "" {
			fmt.Println("[WRN] Please specify an output csv file name with -csv <filename>")
			os.Exit(1)
		} else {
			//Create CSV

			var err error
			csvfile, err = os.Create(*flCsv)
			defer csvfile.Close()

			if err != nil {
				log.Fatalln("failed to open file", err)
			}

		}
	}

	// Check basic correctness if dns mode is passed
	if isFlagPassed("dns") {
		if *flWordlist == "" {
			if !isFlagPassed("crt") {
				fmt.Println("[WRN] -dns mode requires a wordlist or -crt mode")
				os.Exit(1)
			}
		} else {
			//Check if file exists
			if _, err := os.Stat(*flWordlist); err == nil {
			} else {
				fmt.Println("[WRN] Error: file specified with -wordlist does not exist: ", *flWordlist)
				os.Exit(1)
			}
		}
		if isFlagPassed("ptr") {
			fmt.Println("[WRN] Please specify either -dns or -ptr mode - not both")
			os.Exit(1)
		}
	}

	// Load cloudflare ipv4 txt data
	var err error
	cfprefixes, err = loadCFPrefixes(cfipv4txt)
	if err != nil {
		fmt.Println("[ERR] Error reading file:", err)
		return
	}

	doprefixes, err = loadDOPrefixes(docsv)
	if err != nil {
		fmt.Println("[ERR] Error reading file:", err)
		return
	}

	// Load aws.json data
	jsonFile, err := os.Open(awsjson)
	if err != nil {
		fmt.Println(err)
	}

	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Opened AWS aws.json")
	}

	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(byteValue, &prefixes)
	json.Unmarshal(byteValue, &prefixesv6)

	// Iterate through all of the IPv4 prefixes for AWS
	var aws1 int = 0
	for i := 0; i < len(prefixes.Prefixes); i++ {
		if isFlagPassed("verbose") {
		}
		aws1++
	}

	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Parsed AWS IPv4 prefixes: ", aws1)
	}

	// Iterate through all the IPv6 prefixes
	var aws2 int = 0
	for i := 0; i < len(prefixesv6.Prefixesv6); i++ {
		if isFlagPassed("verbose") {
		}
		aws2++
	}
	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Parsed AWS IPv6 prefixes: ", aws2)
	}
	//Finished parsing aws

	// Loading Azure
	jsonFileAzure, err := os.Open(azurejson)
	if err != nil {
		fmt.Println(err)
	}

	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Opened Azure azure.json")
	}
	defer jsonFileAzure.Close()

	byteValueA, _ := ioutil.ReadAll(jsonFileAzure)

	json.Unmarshal(byteValueA, &values)

	// Iterate through all of the Azure IPv4 prefixes
	var azure1 int = 0
	for i := 0; i < len(values.Values); i++ {
		if isFlagPassed("verbose") {
		}
		for i := 0; i < len(values.Values[i].Properties.Addressprefixes); i++ {
			azure1++
		}
	}
	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Parsed Azure prefixes: ", azure1)
	}
	// End of Azure parsing section

	defer jsonFileAzure.Close()

	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Opened cloud.json")
	}
	byteValueG, err := ioutil.ReadFile(googlejson)
	if err != nil {
		fmt.Print(err)
	}

	json.Unmarshal(byteValueG, &gprefixes)

	// Iterate through all of the IPv4 prefixes
	var gcount1 int = 0
	for i := 0; i < len(gprefixes.GPrefixes); i++ {
		if len(gprefixes.GPrefixes[i].Ipv4prefix) > 0 {
			//fmt.Println("IPv4 Prefix: " + gprefixes.GPrefixes[i].Ipv4prefix)
		} else if len(gprefixes.GPrefixes[i].Ipv6prefix) > 0 {
			//fmt.Println("IPv6 Prefix: " + gprefixes.GPrefixes[i].Ipv6prefix)
		} else {

		}
		gcount1++
	}
	if isFlagPassed("verbose") {
		fmt.Println("[VERBOSE] Parsed GCloud prefixes: ", gcount1)
	}
	// end of Gcloud

	// run single IP prefix lookup
	if *flSingle != "" {
		if silentFlag == false {
			fmt.Println("[INF] Single IP prefix lookup of", *flSingle)
		}
		ip_addr := *flSingle
		var pdesc = ""
		if retval1, desc := prefixes.aws_lookup(ip_addr); retval1 {
			pdesc = desc
		} else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
			pdesc = desc2
		} else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
			pdesc = desc3
		} else if retval4, desc4 := cfprefixes.cf_lookup(ip_addr); retval4 {
			pdesc = desc4
		} else if retval5, desc5 := doprefixes.do_lookup(ip_addr); retval5 {
			pdesc = desc5
		} else {
			pdesc = ""
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)

		// Print summary [INF]
		if silentFlag == false {
			if pdesc == "" {
				//empty string, didn't match to a cloud provider
			} else {

				desc_elements := strings.Split(pdesc, ";")
				provider := desc_elements[0]
				provider_elements := strings.Split(provider, ":")
				csp := provider_elements[1]
				prefix := desc_elements[1]
				prefix_elements := strings.Split(prefix, ":")
				csp_prefix := prefix_elements[1]

				s := fmt.Sprintf("[INF] Matched IP [%s] to Cloud Provider via prefix [%s:%s]", ip_addr, csp, csp_prefix)
				fmt.Println(s)

				// Extract the service if AWS or Azure, extract the region if GCP
				if csp == "AWS" || csp == "Azure" || csp == "GCP" {
					service_string := ""
					region_string := ""
					csp_region := ""
					s := ""
					if csp == "AWS" {
						service_string = desc_elements[3]
						region_string = desc_elements[2]
						regions := strings.Split(region_string, ":")
						csp_region = regions[1]
						services := strings.Split(service_string, ":")
						csp_svc := services[1]
						s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s] and Region [%s]", ip_addr, csp_svc, csp_region)
					} else if csp == "Azure" {
						//Parse azure description for SystemService
						service_string = desc_elements[5]
						services := strings.Split(service_string, ":")
						csp_svc := services[1]
						s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s]", ip_addr, csp_svc)
					} else if csp == "GCP" {
						region_string = desc_elements[2]
						regions := strings.Split(region_string, ":")
						csp_region = regions[1]
						s = fmt.Sprintf("[INF] Matched IP [%s] to Region [%s]", ip_addr, csp_region)
					}
					fmt.Println(s)
				}
			}

		}
		// Print details
		fmt.Fprintf(w, "%s,%s\n", ip_addr, pdesc)
		w.Flush()

		os.Exit(1)
	}

	var results []result

	if isFlagPassed("dns") {
		if silentFlag == false {
			fmt.Println("[INF] Running in DNS mode with workers:", *flWorkerCount)
		}

		if *flWordlist == "" {
			//This means crt mode must have been specified

		} else {

			if silentFlag == false {
				fmt.Println("[INF] Running in DNS mode with wordlist:", *flWordlist)
			}

			fqdns := make(chan string, *flWorkerCount)
			gather := make(chan []result)
			tracker := make(chan empty)

			f, err := os.Open(*flWordlist)
			if err != nil {
				panic(err)
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)

			for i := 0; i < *flWorkerCount; i++ {
				go worker(tracker, fqdns, gather, *flServerAddr)
			}

			go func() {
				for r := range gather {
					results = append(results, r...)
				}
				var e empty
				tracker <- e
			}()

			for scanner.Scan() {
				fqdns <- fmt.Sprintf("%s.%s", scanner.Text(), *flDomain)
			}

			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}

			close(fqdns)
			for i := 0; i < *flWorkerCount; i++ {
				<-tracker
			}
			close(gather)
			<-tracker
		}
	}

	if isFlagPassed("crt") {
		if silentFlag == false {
			fmt.Println("[INF] Running certificate transparency lookup crt.sh")
		}
		// Cert Transparency lookup
		crt_results := crt_transparency(*flDomain, *flServerAddr)
		results = append(results, crt_results...)
	}

	if isFlagPassed("prefix") && !isFlagPassed("dns") {

		// If true, process the IP address host list with -ip option
		if *flIp != "" {

			// Open up the IP address text file
			f, err := os.Open(*flIp)

			if err != nil {
				log.Fatal(err)
			}

			defer f.Close()

			scanner := bufio.NewScanner(f)

			// Write the csv file
			x := csv.NewWriter(csvfile)
			defer x.Flush()

			for scanner.Scan() {

				ip_addr := scanner.Text()

				var pdesc = ""

				if isFlagPassed("verbose") {
					fmt.Println("[VERBOSE] Looking up", ip_addr)
				}

				if retval1, desc := prefixes.aws_lookup(ip_addr); retval1 {
					pdesc = desc
				} else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
					pdesc = desc2
				} else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
					pdesc = desc3
				} else if retval4, desc4 := cfprefixes.cf_lookup(ip_addr); retval4 {
					pdesc = desc4
				} else if retval5, desc5 := doprefixes.do_lookup(ip_addr); retval5 {
					pdesc = desc5
				} else {
					pdesc = ""
				}

				w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)

				// Print summary [INF]
				if silentFlag == false {
					if pdesc == "" {
						//empty string, didn't match to a cloud provider
					} else {

						desc_elements := strings.Split(pdesc, ";")
						provider := desc_elements[0]
						provider_elements := strings.Split(provider, ":")
						csp := provider_elements[1]
						prefix := desc_elements[1]
						prefix_elements := strings.Split(prefix, ":")
						csp_prefix := prefix_elements[1]

						s := fmt.Sprintf("[INF] Matched IP [%s] to Cloud Provider via prefix [%s:%s]", ip_addr, csp, csp_prefix)
						fmt.Println(s)

						// Extract the service if AWS or Azure, extract the region if GCP
						if csp == "AWS" || csp == "Azure" || csp == "GCP" {
							service_string := ""
							region_string := ""
							csp_region := ""
							s := ""
							if csp == "AWS" {
								service_string = desc_elements[3]
								region_string = desc_elements[2]
								regions := strings.Split(region_string, ":")
								csp_region = regions[1]
								services := strings.Split(service_string, ":")
								csp_svc := services[1]
								s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s] and Region [%s]", ip_addr, csp_svc, csp_region)
							} else if csp == "Azure" {
								//Parse azure description for SystemService
								service_string = desc_elements[5]
								services := strings.Split(service_string, ":")
								csp_svc := services[1]
								s = fmt.Sprintf("[INF] Matched IP [%s] to Cloud Service [%s]", ip_addr, csp_svc)
							} else if csp == "GCP" {
								region_string = desc_elements[2]
								regions := strings.Split(region_string, ":")
								csp_region = regions[1]
								s = fmt.Sprintf("[INF] Matched IP [%s] to Region [%s]", ip_addr, csp_region)
							}
							fmt.Println(s)
						}
					}
				}
				// Print details
				fmt.Fprintf(w, "%s,%s\n", ip_addr, pdesc)
				w.Flush()

				if isFlagPassed("output") {
					record := []string{ip_addr, pdesc}
					if err := x.Write(record); err != nil {
						log.Fatalln("Error writing record to file:", err)
					}
				}

			}
		} else if *flNmap != "" {
			xmlFile, err := os.Open(*flNmap)
			if err != nil {
				fmt.Println(err)
			} else {
				if silentFlag == false {
					fmt.Println("[INF] Opened nmap file for analysis:", *flNmap)
				}
			}

			defer xmlFile.Close()

			byteValue, _ := ioutil.ReadAll(xmlFile)

			//var nmaprun Nmaprun
			nmaprun := Nmaprun{}

			xml.Unmarshal(byteValue, &nmaprun)

			// Write the csv file
			x := csv.NewWriter(csvfile)
			defer x.Flush()

			for i := 0; i < len(nmaprun.Hosts); i++ {
				if nmaprun.Hosts[i].Status.State == "up" {
					// Only run lookup on hosts that are up

					var pdesc = ""

					//fmt.Println("Host Address: " + nmaprun.Hosts[i].Address.Addr)
					ip_addr := nmaprun.Hosts[i].Address.Addr

					if isFlagPassed("verbose") {
						fmt.Println("[+] Looking up", ip_addr)
					}

					if retval1, desc := prefixes.aws_lookup(ip_addr); retval1 {
						pdesc = desc
					} else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
						pdesc = desc2
					} else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
						pdesc = desc3
					} else if retval4, desc4 := cfprefixes.cf_lookup(ip_addr); retval4 {
						pdesc = desc4
					} else if retval5, desc5 := doprefixes.do_lookup(ip_addr); retval5 {
						pdesc = desc5
					} else {
						pdesc = ""
					}

					w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
					fmt.Fprintf(w, "%s,%s\n", ip_addr, pdesc)
					w.Flush()

					if isFlagPassed("output") {
						record := []string{ip_addr, pdesc}
						if err := x.Write(record); err != nil {
							log.Fatalln("Error writing record to file:", err)
						}
					}

				} else if nmaprun.Hosts[i].Status.State == "down" {
				} else {
				}
			}
		}
	}

	if isFlagPassed("ptr") {

		// If true, process the IP address host list with -ip option
		if *flIp != "" {

			// Open up the IP address text file
			f, err := os.Open(*flIp)

			// report error
			if err != nil {
				//log.Fatal(err)
			}

			// defer close
			defer f.Close()

			scanner := bufio.NewScanner(f)

			// Write the csv file
			x := csv.NewWriter(csvfile)
			defer x.Flush()

			for scanner.Scan() {

				ip_addr := scanner.Text()

				if isFlagPassed("verbose") {
					fmt.Println("[+] Looking up", ip_addr)
				}

				ptr := reverse(ip_addr)
				if len(ptr) > 0 {
					w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
					fmt.Fprintf(w, "%s,%s\n", ip_addr, ptr)
					w.Flush()

					if isFlagPassed("output") {
						record := []string{ip_addr, ptr}
						if err := x.Write(record); err != nil {
							log.Fatalln("Error writing record to file:", err)
						}
					}
				}

			}
		} else if *flNmap != "" {

			xmlFile, err := os.Open(*flNmap)
			if err != nil {
				fmt.Println(err)
			} else {
				if silentFlag == false {
					fmt.Println("[INF] Opened nmap file for analysis:", *flNmap)
				}
			}

			defer xmlFile.Close()

			byteValue, _ := ioutil.ReadAll(xmlFile)

			//var nmaprun Nmaprun
			nmaprun := Nmaprun{}

			xml.Unmarshal(byteValue, &nmaprun)

			// Write the csv file
			x := csv.NewWriter(csvfile)
			defer x.Flush()

			for i := 0; i < len(nmaprun.Hosts); i++ {
				if nmaprun.Hosts[i].Status.State == "up" {
					// Only run lookup on hosts that are up

					ip_addr := nmaprun.Hosts[i].Address.Addr

					if isFlagPassed("verbose") {
						fmt.Println("[+] Looking up", ip_addr)
					}

					ptr := reverse(ip_addr)
					if len(ptr) > 0 {

						w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
						fmt.Fprintf(w, "%s,%s\n", ip_addr, ptr)
						w.Flush()

						if isFlagPassed("output") {
							record := []string{ip_addr, ptr}
							if err := x.Write(record); err != nil {
								log.Fatalln("Error writing record to file:", err)
							}
						}
					}

				} else if nmaprun.Hosts[i].Status.State == "down" {
				} else {
				}
			}

		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
	for _, r := range results {
		// print summary [INF]
		if silentFlag == false {
			if r.Source == "Certificate" {
				s := fmt.Sprintf("[INF] Found host via crt.sh [%s]", r.Hostname)
				fmt.Println(s)
			}
		}

		// print details
		fmt.Fprintf(w, "%s,%s,%s,%s,%s\n", r.Hostname, r.IPAddress, r.Source, r.CNAME_Response, r.Description)

		records_found++
	}
	w.Flush()

	// Write the csv file
	x := csv.NewWriter(csvfile)
	defer x.Flush()

	if isFlagPassed("output") {
		for _, r := range results {
			record := []string{r.Hostname, r.IPAddress, r.Source, r.CNAME_Response, r.Description}
			if err := x.Write(record); err != nil {
				log.Fatalln("Error writing record to file:", err)
			}
		}
	}

	if silentFlag == false {

		if dnsFlag == true {
			fmt.Println("[INF] Timeout errors: ", error_timeout)
		}

	}
	duration := time.Since(start)

	if silentFlag == false {

		if dnsFlag == true && crtFlag == true {
			fmt.Println("[INF] Duration:", duration)
		}

		if dnsFlag == true {
			fmt.Println("[INF] DNS Lookups:", dns_lookups)
		}
		if crtFlag == true {
			fmt.Println("[INF] Certificate Records found:", records_found)
		}
	}
}
