package main

import (
    "bufio"
    "io/ioutil"
    "fmt"
    "log"
    "flag"
    "os"
    "net"
    "github.com/miekg/dns"
    "strings"
    "text/tabwriter"
    "net/http"
    "golang.org/x/net/html"
    "encoding/json"
    "encoding/xml"
    "encoding/csv"
    "time"
)

/* Global Variables */
var prefixes Prefixes
var prefixesv6 Prefixesv6
var values Values
var gprefixes GPrefixes
var csvfile *os.File 
var error_timeout = 0
var dns_lookups = 0
var records_found = 0

func fwd_dns_request(query string, serverAddr string) []result {

    var results []result 
    var fqdn = strings.TrimSuffix(query,".")
    var source = "A"
    var cname_response = ""
    var pdesc = ""
    dns_lookups++

    var m dns.Msg
    m.SetQuestion(dns.Fqdn(query), dns.TypeA)
    in, err := dns.Exchange(&m, serverAddr)

    if isFlagPassed("verbose"){
        fmt.Println("[+] Looking up", fqdn)
    }

    if err != nil {
        error_timeout++
        if isFlagPassed("verbose"){
            fmt.Println("Error:",err)
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
	//records_found++

	ip_addr := a.A.String()

	if isFlagPassed("prefix"){
	    if retval1, desc := prefixes.aws_lookup(ip_addr); retval1{
	        pdesc = desc
            } else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
	        pdesc = desc2
            } else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
	        pdesc = desc3
            } else {
	        pdesc = ""
            }
	    results = append(results, result{IPAddress:  a.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})
	}

        results = append(results, result{IPAddress:  ip_addr, Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc})

    } else if a, ok := in.Answer[0].(*dns.CNAME); ok {
        source = "CNAME"
        for _, s := range in.Answer  {

	    // increment records found
	    //records_found++

            if cresp, ok := s.(*dns.A); ok {
	        cname_response = strings.TrimSuffix(a.Target,".")
	        source = "A"

	        ip_addr := cresp.A.String()

                if isFlagPassed("prefix"){
	            if retval1, desc := prefixes.aws_lookup(ip_addr); retval1{
                        pdesc = desc
                    } else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
                        pdesc = desc2
                    } else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
                        pdesc = desc3
                    } else {
		        pdesc = ""
                    }
                    results = append(results, result{IPAddress:  cresp.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc}) 
                }

                results = append(results, result{IPAddress:  cresp.A.String(), Hostname: fqdn, Source: source, CNAME_Response: cname_response, Description: pdesc}) 

	    } else if cresp, ok := s.(*dns.CNAME); ok {
	        source = "CNAME"
		hostname := cresp.Header().Name
	        fqdn = strings.TrimSuffix(cresp.Target,".")
                results = append(results, result{IPAddress:  "", Hostname: hostname, Source: source, CNAME_Response: fqdn, Description: pdesc}) 
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
        if strings.Contains(v, domain_string) && !strings.HasPrefix(v, "*."){

		if strings.Contains(v, "Type: Identity") {
		// Remove the first line
		} else {

                    results = append(results, result{IPAddress:  "", Hostname: v, Source: "Certificate", CNAME_Response: ""}) 
                    sum += 1

		    if isFlagPassed("dns") {

                        // Write the csv file
                        x := csv.NewWriter(csvfile)
                        defer x.Flush()

                        lookup := v + "."
			result := fwd_dns_request(lookup, serverAddr)

			w := tabwriter.NewWriter(os.Stdout, 0, 8, 4, ' ', 0)
                        for _, r := range result {
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
        IPAddress string
        Hostname  string
	Source 	  string
	CNAME_Response string
	Description string
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
	    // This is Ipv4 prefix
            _, ipv4Net,_  := net.ParseCIDR(s.GPrefixes[i].Ipv4prefix)
            mybool := ipv4Net.Contains(IPAddress)
            if mybool == true{
		description := fmt.Sprintf("Provider:GCP;Prefix:%s",s.GPrefixes[i].Ipv4prefix)
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

func (s *Prefixes) aws_lookup(lookup string) (bool, string) {

    var description = ""

    for i := 0; i < len(s.Prefixes); i++ {
        IPAddress := net.ParseIP(lookup)
        _, ipv4Net,_  := net.ParseCIDR(s.Prefixes[i].Ip_prefix)
        mybool := ipv4Net.Contains(IPAddress)
        if mybool == true{
		description := fmt.Sprintf("Provider:AWS;Prefix:%s;Region:%s;Service:%s",s.Prefixes[i].Ip_prefix,s.Prefixes[i].Region,s.Prefixes[i].Service) 

		if isFlagPassed("verbose") {
                    fmt.Println("    [+] Found AWS prefix:", s.Prefixes[i].Ip_prefix)
                    fmt.Println("        [+] Region: ",s.Prefixes[i].Region)
                    fmt.Println("        [+] Service: ",s.Prefixes[i].Service)
                }
                return true, description
        }
    }
    return false, description
}

func (s *Values) azure_lookup(lookup string) (bool, string) {
    IPAddress := net.ParseIP(lookup)

    var description = ""

    for z := 0; z < len(s.Values); z++ {
        for i := 0; i < len(s.Values[z].Properties.Addressprefixes); i++ {

            _, ipv4Net,_  := net.ParseCIDR(s.Values[z].Properties.Addressprefixes[i])
            mybool := ipv4Net.Contains(IPAddress)
            if mybool == true{

		description := fmt.Sprintf("Provider:Azure;Prefix:%s;Name:%s;ID:%s;Platform:%s;SystemService:%s",s.Values[z].Properties.Addressprefixes[i],s.Values[z].Name,s.Values[z].Id,s.Values[z].Properties.Platform,s.Values[z].Properties.Systemservice) 
		if isFlagPassed("verbose") {
                    fmt.Println("    [+] Found Azure prefix:", s.Values[z].Properties.Addressprefixes[i])
                    fmt.Println("        [+] Name: ",s.Values[z].Name)
                    fmt.Println("        [+] ID: ",s.Values[z].Id)
                    fmt.Println("        [+] Platform: ",s.Values[z].Properties.Platform)
                    fmt.Println("        [+] SystemService: ",s.Values[z].Properties.Systemservice)
		}
                return true, description 
            }

        }
    }

    return false, description 

}

// Nmap structures
type Nmaprun struct {
        XMLName xml.Name `xml:"nmaprun"`
        Hosts    []Hosts  `xml:"host"`
}

type Hosts struct {
        XMLName xml.Name `xml:"host"`
        Status   Status   `xml:"status"`
        Address  Address  `xml:"address"`
}

type Status struct {
    XMLName  xml.Name `xml:"status"`
    State string   `xml:"state,attr"`
}

type Address struct {
    XMLName  xml.Name `xml:"address"`
    Addr string   `xml:"addr,attr"`
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
        Region    string `json:"region"`
        Service   string `json:"service"`
        NBG       string `json:"network_border_group"`
}
// End of AWS Structures


// Start of Azure Structures
type Values struct {
        Values []Value `json:"values"`
}

type Value struct {
        Name string  `json:"name"`
        Id    string `json:"id"`
        Properties  Properties `json:"properties"`
}

type Properties struct {
        Changenumber string  `json:"changeNumber"`
        Region string    `json:"region"`
        Regionid string  `json:"regionId"`
        Platform string  `json:"platform"`
        Systemservice string  `json:"systemService"`
        Addressprefixes []string  `json:"addressPrefixes"`
        Networkfeatures []string  `json:"networkFeatures"`
}
// End of Azure Structures

// Start of Gcloud Structures
type GPrefixes struct {
        GPrefixes []GPrefix `json:"prefixes"`
}

type GPrefix struct {
        Ipv4prefix string `json:"ipv4Prefix"`
        Ipv6prefix string `json:"ipv6Prefix"`
}
// End of Gcloud Structures



func main() {

    var (
        flDomain      = flag.String("domain", "", "The domain to perform guessing against.")
        flWordlist    = flag.String("wordlist", "", "The wordlist to use for guessing.")
        flCsv         = flag.String("csv", "", "Output results to CSV file")
        flServerAddr  = flag.String("resolver", "8.8.8.8:53", "The DNS server to use.")
	flIp          = flag.String("ip", "", "The text file to use with IP addresses")
	flNmap        = flag.String("nmap", "", "Nmap scan xml file to use.")
	flWorkerCount = flag.Int("workers", 10, "The amount of workers to use.")
	ptrFlag       = false
	prefixFlag    = false
	crtFlag       = false
	dnsFlag       = false
	verboseFlag   = false
	outputFlag    = false
    )

    start := time.Now()

    flag.BoolVar(&ptrFlag, "ptr", false, "PTR lookup mode")
    flag.BoolVar(&prefixFlag, "prefix", false, "IP Prefix CSP lookup mode")
    flag.BoolVar(&crtFlag, "crt", false, "Certificate transparency lookup mode")
    flag.BoolVar(&dnsFlag, "dns", false, "A and CNAME record lookup mode")
    flag.BoolVar(&verboseFlag, "verbose", false, "Enable verbose output")
    flag.BoolVar(&outputFlag, "output", false, "Enable output to CSV")

    flag.Parse()

    if *flDomain == "" && *flIp == "" && *flNmap == "" {
        fmt.Println("-domain or -ip or -nmap mode is required")
	fmt.Println("Example 1:  -domain acme.com")
	fmt.Println("Example 2:  -ip hosts.txt -ptr")
	fmt.Println("Example 3:  -ip hosts.txt -prefix")
        os.Exit(1)
    }

    if *flDomain != "" {
        if ! isFlagPassed("crt") && ! isFlagPassed("dns") {
            fmt.Println("Either -crt or -dns mode must be specified with -domain <domain>")            
	    fmt.Println("Example 1:  -domain acme.com -dns")
	    fmt.Println("Example 2:  -domain acme.com -crt")
            os.Exit(1)
	}
    }

    if *flIp != "" && *flNmap != "" {
        fmt.Println("[-] Please select either -ip or -nmap when using reverse lookup mode")
	    fmt.Println("Example 1:  -domain acme.com -dns")
            os.Exit(1)
    }

    // Check if ip address list is specified
    if *flIp == "" {
    } else {
      if isFlagPassed("crt") {
          fmt.Println("The IP address mode (-ip) can't be enabled with -crt mode")
          os.Exit(1)
      } else if isFlagPassed("dns") {
          fmt.Println("The IP address mode (-ip) can't be enabled with -dns mode")
          os.Exit(1)
      }

      if isFlagPassed("ptr") || isFlagPassed("prefix") {
      } else {
          fmt.Println("Please select either -ptr or -prefix when specifying an IP address list (-ip)")
          os.Exit(1)
      }
    }

    // For now only allow -prefix or -ptr:  Not both
    if isFlagPassed("ptr") && isFlagPassed("prefix") {
        fmt.Println("Please specify either PTR mode (-ptr) or Prefix mode (-prefix)")
        fmt.Println("Both flags are set and this is not allowed")
        os.Exit(1)
    }

    if isFlagPassed("output") {
        if *flCsv == "" {
            fmt.Println("Please specify an output csv file name with -csv <filename>")
            os.Exit(1)
        } else {
	    //Create CSV
            //csvfile, err = os.Create(*flCsv)
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
            if ! isFlagPassed("crt") {
                fmt.Println("-dns mode requires a wordlist or -crt mode")
                os.Exit(1)
	    }
	} else {
		//Check if file exists
		if _, err := os.Stat(*flWordlist); err == nil{
                } else {
			fmt.Println("[-] Error: file specified with -wordlist does not exist: ",*flWordlist)
                        os.Exit(1)
		}
	}
        if isFlagPassed("ptr"){
            fmt.Println("Please specify either -dns or -ptr mode - not both")
            os.Exit(1)
        }
    }

    jsonFile, err := os.Open("ip-ranges.json")
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println("[+] Opened AWS ip-ranges.json")
    defer jsonFile.Close()

    byteValue, _ := ioutil.ReadAll(jsonFile)

    json.Unmarshal(byteValue, &prefixes)
    json.Unmarshal(byteValue, &prefixesv6)

    // Iterate through all of the IPv4 prefixes for AWS
    var aws1 int = 0
    for i := 0; i < len(prefixes.Prefixes); i++ {
        if isFlagPassed("verbose"){
            //fmt.Println("IP Prefix: " + prefixes.Prefixes[i].Ip_prefix)
            //fmt.Println("Region: " + prefixes.Prefixes[i].Region)
            //fmt.Println("Service: " + prefixes.Prefixes[i].Service)
            //fmt.Println("NBG: " + prefixes.Prefixes[i].NBG)
            //fmt.Println("Parsed AWS IPv4: ",i)
	}
        aws1++
    }
    fmt.Println("[+] Parsed AWS IPv4 prefixes: ",aws1)

    // Iterate through all of the IPv6 prefixes
    var aws2 int = 0
    for i := 0; i < len(prefixesv6.Prefixesv6); i++ {
        if isFlagPassed("verbose"){
            //fmt.Println("IP Prefix: " + prefixesv6.Prefixesv6[i].Ipv6_prefix)
            //fmt.Println("Region: " + prefixesv6.Prefixesv6[i].Region)
            //fmt.Println("Service: " + prefixesv6.Prefixesv6[i].Service)
            //fmt.Println("NBG: " + prefixesv6.Prefixesv6[i].NBG)
            //fmt.Println("Parsed AWS IPv6",i)
	}
        aws2++
    }
    fmt.Println("[+] Parsed AWS IPv6 prefixes: ",aws2)
    //Finished parsing aws

    // Loading Azure
    jsonFileAzure, err := os.Open("azure.json")
    if err != nil {
        fmt.Println(err)
    }

    fmt.Println("[+] Opened azure.json")
    defer jsonFileAzure.Close()

    byteValueA, _ := ioutil.ReadAll(jsonFileAzure)

    json.Unmarshal(byteValueA, &values)

    // Iterate through all of the Azure IPv4 prefixes
    var azure1 int = 0
    for i := 0; i < len(values.Values); i++ {
        if isFlagPassed("verbose"){
            //fmt.Println("Name: " + values.Values[i].Name)
            //fmt.Println("Id: " + values.Values[i].Id)
            //fmt.Println("Platform: " + values.Values[i].Properties.Platform)
            //fmt.Println("SystemService: " + values.Values[i].Properties.Systemservice)
        }
        for i := 0; i < len(values.Values[i].Properties.Addressprefixes); i++ {
            azure1++
        }
        // Loop and print network features
        //fmt.Println("Parsed ",i)
        //for i, s := range values.Values[i].Properties.Networkfeatures {
        //    fmt.Println(i, s)
        //}
    }
    fmt.Println("[+] Parsed Azure prefixes: ",azure1)
    // End of Azure parsing section

    defer jsonFileAzure.Close()

    fmt.Println("[+] Opened goog.json")
    byteValueG, err := ioutil.ReadFile("./goog.json")
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
        //fmt.Println("Parsed ",i)
        gcount1++
    }
    fmt.Println("[+] Parsed GCloud prefixes: ",gcount1)
    // end of Gcloud
    // End of all three CSP parsing

    var results []result

    if isFlagPassed("dns") {
	fmt.Println("[+] Running in DNS mode with workers:", *flWorkerCount)

        if *flWordlist == "" {
            //This means crt mode must have been specified 

	} else {

	    fmt.Println("[+] Running in DNS mode with wordlist:", *flWordlist)

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
        fmt.Println("[+] Running certificate transparency lookup crt.sh")
        // Cert Transparency lookup
        crt_results := crt_transparency(*flDomain, *flServerAddr)
        results = append(results, crt_results...)
    }

    if isFlagPassed("prefix") && ! isFlagPassed("dns") {

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
                    fmt.Println("[+] Looking up",ip_addr)
	        }

	        if retval1, desc := prefixes.aws_lookup(ip_addr); retval1{
		    pdesc = desc
	        } else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 { 
		    pdesc = desc2
	        } else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 { 
		    pdesc = desc3
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

            }
        } else if *flNmap != "" {
            xmlFile, err := os.Open(*flNmap)
            if err != nil {
                fmt.Println(err)
            } else {
	        fmt.Println("[+] Opened nmap file for analysis:", *flNmap)
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
                        fmt.Println("[+] Looking up",ip_addr)
                    }

	            if retval1, desc := prefixes.aws_lookup(ip_addr); retval1{
		        pdesc = desc
                    } else if retval2, desc2 := values.azure_lookup(ip_addr); retval2 {
		        pdesc = desc2
                    } else if retval3, desc3 := gprefixes.gcloud_lookup(ip_addr); retval3 {
		        pdesc = desc3
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
                    fmt.Println("[+] Looking up",ip_addr)
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
                fmt.Println("[+] Opened nmap file for analysis:", *flNmap)
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
                        fmt.Println("[+] Looking up",ip_addr)
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

    fmt.Println("Timeout errors: ",error_timeout)
    duration := time.Since(start)

    fmt.Println("Duration:",duration)
    fmt.Println("DNS Lookups:",dns_lookups)
    fmt.Println("DNS Records found:",records_found)

}
