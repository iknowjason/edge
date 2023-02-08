# Cloud edge
 *Lookup an IP to find the cloud provider and other details based on the provider's published JSON data* 

Cloud edge is a recon tool focused on exploring cloud service providers.  It can be used for cloud attribution and forensics, pentesting, bug bounty, red teaming, or general R&D of cloud providers.  Edge automatically loads Cloud Service Provider (CSP) published IP address ranges (AWS, Azure, GCP) JSON files and performs a prefix lookup based on the input IP address.  Can be used to integrate in with other recon tooling.  In a black box network pentest, edge quickly discovers which cloud CSP the customer is hosted with, or just double-verifying the scope for rules of engagement.  Each of the big three CSPs (Amazon, Azure, GCP) publish a list of all of their IP prefixes and/or netblocks.  In some cases this also includes the region/data center and service name.  This can be useful for recon and this tool can quickly parse and do a lookup based on IP prefix.

![](edge-usage.png)


# Input and Output
Here are a few notes on how the tool works for inputs and output.  

## JSON files from cloud providers

When the tool runs, it automatically tries to download and load the three cloud provider IP address ranges JSON files to the working directory.  Here is how it works:

By default it will attempt to download the three files from the URLs below unless you disable the automated download with (-nd) flag.
* ip-ranges.json (AWS) --> https://ip-ranges.amazonaws.com/ip-ranges.json
* azure.json (Azure) --> (URL that periodically needs to be updated)
* goog.json (GCP) --> https://www.gstatic.com/ipranges/goog.json

These three files are already included in this github repository, so downloading them will update any necessary changes.  Once downloaded, you can run the tool with ```-nd``` to avoid superfluous downloads.

If found in working directory, all IP prefixes are loaded into memory.  The cloud provider IP ranges json files always attempt to load from the working directory.  Enabling the actual lookup is done with  the ```-prefix``` flag. 

When ```-dns``` mode is enabled, DNS lookups for both A and CNAME records are buffered without display until all DNS queries are finished.  After the queries are finished, the output is displayed.

One idea is to initially run the tool to download all three files, making sure they are up-to-date.  Then subsequent runs with ```-nd``` to improve performance and not download every run.

## Default [INF] Mode enabled

By the default the output displays Informational messages starting with ```[INF]```.  This can be disabled with ```-silent``` flag.  The output will look like this:
```
./edge -single 140.179.144.130
[INF] Single IP prefix lookup of 140.179.144.130
[INF] Matched IP [140.179.144.130] to Cloud Provider via prefix [AWS:140.179.144.128/25]
[INF] Matched IP [140.179.144.130] to Cloud Service [API_GATEWAY] and Region [cn-north-1]
140.179.144.130,Provider:AWS;Prefix:140.179.144.128/25;Region:cn-north-1;Service:API_GATEWAY
```

Informational messages will tell you if a record is found through a DNS 'A' record, DNS 'CNAME' record, Certificate (crt.sh), or if a prefix match is found.  Prefix matches will tell you the cloud provider detected with the matching prefix, as well as the cloud service and region if applicable.  Azure regions are not currently detected but AWS ones are.

## Default CSV Output

With ```-dns``` or ```crt``` mode, the output is is sent by default to the console as comma delimited results.  This makes it easy to use other tools to parse these results.
```
FQDN,IP,SOURCE,CNAME,DESCRIPTION
```

* **FQDN:**  This is the DNS lookup as a FQDN.
* **IP:**  This is the IP address returned from an A record if found.
* **SOURCE:**  This is the source of the lookup.  Either A, CNAME, or Certificate.
* **CNAME:** This returns the CNAME or ALIAS if the request is a CNAME.
* **DESCRIPTION:** This returns any results from the IP address ranges description if ```-prefix``` is enabled.

With ```-prefix``` mode and either ```-ip``` or ```-nmap```, the output is sent by default to the console as comma delimited results:

```
IP,DESCRIPTION
```

The ```IP``` is the IP address and the ```DESCRIPTION``` is the results from the IP address ranges lookup in the cloud provider IP address ranges JSON files, if applicable.


With ```-ptr``` mode and either ```ip``` or ```nmap```, the output is sent by default to the console as comma delimited results:
```
IP,PTR
```

The ```IP``` is the IP address and the ```PTR``` is the results from the DNS PTR lookup if found.

## IP Address files with -IP
The ```-ip``` flag signals to iterate through a list of IP addresses and can be used in ```prefix``` or ```ptr``` mode.  When you run the tool with ```-ip <hosts.txt>```, it expects each IP address in a separate line, and will iterate through the list doing lookups.  Here is an example of the file contents:
```
user@host:~/demo$ cat ip.txt 
3.133.110.237
18.117.232.92
18.221.247.211
3.137.199.52
```

## Nmap XML files
The ```-nmap``` flag signals to parse an nmap XML file.  It will look for any host in the nmap scan file marked as "Up."  For example, ```-nmap scan1.xml``` will tell the tool to parse the scan1.xml file and look for any hosts marked as Up by nmap.  You then run it with either -ptr or -prefix to do a lookup of the IP.

## Subdomain enumeration with -wordlist
The tool performs classic subdomain enumeration by iterating through a wordlist containing hostnames, one hostname per line.  This is used in ```-dns``` mode with ```-wordlist <hosts.txt>```.  An example of what this looks like for the hosts.txt file:

```
user@host:~/demo$ more subdomains-5k.txt 
www
blog
news
blogs
en
online
```

# Options
```
$ edge -help
Usage of edge:
  -crt
    	Certificate transparency lookup mode
  -csv string
    	Output results to CSV file
  -dns
    	A and CNAME record lookup mode
  -domain string
    	The domain to perform guessing against.
  -ip string
    	The text file to use with IP addresses
  -nd
    	Disable (nd or no download) automated download of provider prefixes
  -nmap string
    	Nmap scan xml file to use.
  -output
    	Enable output to CSV
  -prefix
    	IP Prefix CSP lookup mode
  -ptr
    	PTR lookup mode
  -resolver string
    	The DNS server to use. (default "8.8.8.8:53")
  -silent
    	Enable silent mode to suppress [INF]
  -single string
    	Single IP address to do a prefix lookup
  -verbose
    	Enable verbose output
  -wordlist string
    	The wordlist to use for guessing.
  -workers int
    	The amount of workers to use. (default 10)
```

# Examples

Look up a single IP address
```
edge -single <ip_address>
```

**Description:**  Perform a prefix lookup of a single IP address supplied with ```<ip_addr>``` against the cloud provider's JSON files.

**Sample Output:**
```
edge -single 140.179.144.130
[INF] Single IP prefix lookup of 140.179.144.130
[INF] Matched IP [140.179.144.130] to Cloud Provider via prefix [AWS:140.179.144.128/25]
[INF] Matched IP [140.179.144.130] to Cloud Service [API_GATEWAY] and Region [cn-north-1]
140.179.144.130,Provider:AWS;Prefix:140.179.144.128/25;Region:cn-north-1;Service:API_GATEWAY
```

***
Look up a single IP address and suppress Info messages
```
$ edge -single <ip_address> -silent
```

**Description:**  Same as above, except enable the silent mode.  This suppresses the [INF] messages with extra information.

**Sample Output:**
```
edge -single 140.179.144.130
140.179.144.130,Provider:AWS;Prefix:140.179.144.128/25;Region:cn-north-1;Service:API_GATEWAY
```
***
Use local provider JSON files instead of downloading them.

```
edge -single <ip_address> -silent -nd
```

**Description:**  Don't try to download the provider JSON files, but instead use the local files in working directory.

***
Wordlist subdomain enumeration with certificate transparancy and prefix lookup.

```
edge -domain <domain> -dns -crt -prefix -wordlist <wordlist.txt>
```

**Description:**  Perform a wordlist subdomain enumeration of all A and CNAME records based on wordlist.txt against domain with certificate transparency lookup.  For each enumerated host found with Cert transparency, also do a DNS lookup.  Do an IP prefix lookup of the IP address across all three cloud service provider's published list of IP prefixes.

**Sample Output:**
```
edge -domain tesla.com -dns -crt -prefix -wordlist subdomains-5k.txt
[INF] Found host via CNAME [fleetview.prd.na.fn.tesla.com.:fleetview.prd.usw2.fn.tesla.com]
fleetview.prd.na.fn.tesla.com.,,CNAME,fleetview.prd.usw2.fn.tesla.com,
[INF] Found host via CNAME [fleetview.prd.usw2.fn.tesla.com.:a69ff530d53f14d8e8059a3aee44e9ab-1848028946.us-west-2.elb.amazonaws.com]
fleetview.prd.usw2.fn.tesla.com.,,CNAME,a69ff530d53f14d8e8059a3aee44e9ab-1848028946.us-west-2.elb.amazonaws.com,
[INF] Found host via A [a69ff530d53f14d8e8059a3aee44e9ab-1848028946.us-west-2.elb.amazonaws.com:52.39.128.70]
[INF] Matched Cloud Provider via prefix [AWS:52.36.0.0/14]
[INF] Matched IP [52.39.128.70] to Cloud Service [EC2] and Region [us-west-2]
```
***

* **```$ edge -domain <domain> -dns -wordlist <wordlist.txt>```**  

**Description:** Perform just a wordlist scan of all A and CNAME records based on wordlist.

* **```$ edge -domain <domain> -dns -wordlist <wordlist.txt> -prefix```**  

**Description:** Perform just a wordlist scan of all A and CNAME records based on wordlist.  For every IP address enumerated, perform a prefix lookup.

* **```$ edge -domain <domain> -crt```**  

**Description:** Do a Certificate Transparency log lookup using https://crt.sh


* **```$ edge -domain <domain> -dns -crt```**

**Description:** Perform a Certificate transparency lookup.  For each host discovered via Cert Transparency, do a full DNS A or CNAME lookup.

* **```$ edge -prefix -ip <ip-hosts.txt>```**

**Description:** Perform a lookup of the IP address for the cloud service provider IP prefix.  Takes a list of IP addresses in ip-hosts.txt and looks through it doing a lookup.  One IP address per line.

* **```$ edge -ptr -ip <ip-hosts.txt>```**

**Description:** Does a DNS PTR lookup based on the IP address on each line of ip-hosts.txt.

* **```$ edge -prefix -nmap <results.xml>```**

**Description:** Parses an nmap scan XML file, identifying all "Up" hosts.  For every "Up" host in nmap XML scan results, do an IP prefix lookup for the cloud service provider.


* **```$ edge -ptr -nmap <results.txt>```**

**Description:** Parses an nmap scan XML file, and does a PTR lookup of every "Up" host.


* **```$ edge -domain <domain> -dns -wordlist <wordlist.txt> -workers 100```**

**Description:** Uses a DNS concurrency scan of 100 workers.  This increases the scan speed.  Default workers: 10.

* **```$ edge -domain <domain> -dns -wordlist <wordlist.txt> -resolver 8.8.4.4:53```**

**Description:** Specify a DNS resolver of 8.8.4.4 on port 53.  Default is 8.8.8.8.


* **```$ edge -crt -domain <domain> -output -csv <output.csv>```**

**Description:** Output results to a CSV file, output.csv.


* **```$ edge -crt -domain <domain> -verbose```** 

**Description:** Enable verbose output.


# Installing

## Binaries
You can grab the pre-compiled binaries or build it.  Make sure you also get the cloud provider IP prefix JSON files.

## Building
Tested with go1.18

```
$ git clone https://github.com/iknowjason/edge.git
$ cd edge
~/edge$ go build edge.go
~/edge$ ./edge (Verify it)
```



# Credits
@mosesrenegade for tool inspiration

@0xdabbad00 for general AWS tools and inspiration

This tool was inspired from many other tools and authors, including dnsrecon and gobuster.  Yeah I know.  Not a lot new here - just another subdomain enumeration tool.  I just really wanted to learn Golang :-)

"Black Hat Go" book
