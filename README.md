# Description
This script is a wrapper to do an initial recon given an IP or CIDR 

WORK IN PROGRESS

# Usage
./gather.sh -i IP/CIDR || -d file_with_domain [-a] [-s] [-m] [-b]

The script performs passive reconnaissance from an IP/CIDR (-i) or a list of domains(-d) but you can also perform active checks with the -a flag.
The subdomain enumeration isn't enable use -s for enable it
Type of target (either one):

-i IP/CIDR

-d list of domain

Flag:

-a active scan

-s enable subdomain enumeration for -d target

-m enable misconfig-mapper

-b enable Blind XSS check  with Dalfox


The output in save in current directory


# Technologies
[Nuclei](https://github.com/projectdiscovery/nuclei)

[Katana](https://github.com/projectdiscovery/katana)

[Httpx](https://github.com/projectdiscovery/httpx)

[Dnsx](https://github.com/projectdiscovery/dnsx)

[Subfinder](https://github.com/projectdiscovery/subfinder)

[Assetfinder](https://github.com/tomnomnom/assetfinder)

[Findomain](https://github.com/Findomain/Findomain)

[Subfinder](https://github.com/projectdiscovery/subfinder)

[Gowitness](https://github.com/sensepost/gowitness)

[Param](https://github.com/devanshbatham/ParamSpider)

[Dirsearch](https://github.com/maurosoria/dirsearch)

[Secretfinder](https://github.com/m4ll0k/SecretFinder)

[LinkFinder](https://github.com/GerbenJavado/LinkFinder)

[Dalfox](https://github.com/hahwul/dalfox)



# Directory tree

Target
├── log.log
├── nmap
│   ├── all.gnmap
│   ├── all.nmap
│   └── all.xml
├── response
│   ├── domain-target1
│   │   └── domain-target1-headers.txt
│   ├── domain-target2
│   │   └── domain-target2-headers.txt
│   ├── domain-target3
│   │   └── domain-target3-headers.txt
│   ├── domain-target4
│   │   └── domain-target4-headers.txt
├── scans
│   ├── domain-target1
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   └── statics.txt
│   ├── domain-target2
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   └── statics.txt
│   ├── domain-target3
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   └── statics.txt
│   ├── domain-target4
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   └── statics.txt
│   │   └── katana_result.txt
├── scope
│   ├── dns_ptr.txt
│   ├── live_target.txt
│   ├── subdomains.txt
│   └── target.txt
└── screenshot
    ├── gowitness.sqlite3 

