# edge
Edge is a recon tool focused on exploring cloud service providers.  Can be used for pentesting, bug bounty, red teaming, or R&D of cloud providers.  Edge automatically loads CSP IP prefixes (AWS, Azure, GCP) and can do prefix lookups based on IP addressing.  

![](edge-usage.png)

# Demo Video


# Detailed Usage / Examples
```edge -domain <domain> -dns -crt -prefix -wordlist <wordlist.txt>``` : Do a wordlist scan of all A and CNAME records based on wordlist.txt against domain with certificate transparency lookup.  For each enumerated host found with Cert transparency, also do a DNS lookup.  Do an IP prefix lookup of the IP address.


# Building

# Credits
@mosesrenegade for tool inspiration
@0xdabbad00 for general AWS tools and inspiration

This tool was inspired from many other tools and authors, including dnsrecon and gobuster.  Not a lot new here other than combining IP prefix CSP lookups.  Just wanted to learn Golang.

"Black Hat Go" book
