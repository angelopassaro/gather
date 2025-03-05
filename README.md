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

[ParamSpider](https://github.com/devanshbatham/ParamSpider)

[Dirsearch](https://github.com/maurosoria/dirsearch)

[Secretfinder](https://github.com/m4ll0k/SecretFinder)

[LinkFinder](https://github.com/GerbenJavado/LinkFinder)

[Dalfox](https://github.com/hahwul/dalfox)



# Directory tree

```
targets
├── log.log
├── nmap
│   ├── all.gnmap
│   ├── all.nmap
│   └── all.xml
├── response
│   ├── target1.com
│   │   └── 6aeb4976af7d04d273fbc268d70edd15a05ac3a4.txt
│   ├── target2.com
│   │   └── d47ba415661b5d707c37aaef20b63226d273ab4a.txt
│   ├── target3.com
│   │   └── d4057dc19844d8cd0b4d9bb14dce6c979dc32459.txt
│   ├── target4.com
│   │   └── 52bc3d1f01061499a1331125f100616a1f665f54.txt
│   ├── target5.com
│   │   └── 6e04c1b2ac402d25f098831212b525738428297e.txt
│   ├── target6.com
│   │   └── e96d073983bdb0626a3f78903434f37f576c4f3a.txt
│   ├── index.txt
├── scans
│   ├── target1.com
│   │   ├── cves.txt
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
│   ├── target2.com
│   │   ├── cves.txt
│   │   ├── dirsearch_log.txt
│   │   ├── dirsearch.txt
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
│   ├── target3.com
│   │   ├── cves.txt
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
│   ├── target4.com
│   │   ├── cves.txt
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
│   ├── target5.com
│   │   ├── cves.txt
│   │   ├── dalfox.log
│   │   ├── dalfox.txt
│   │   ├── findings
│   │   │   ├── 1.txt
│   │   │   ├── 2.txt
│   │   │   ├── 3.txt
│   │   │   ├── 4.txt
│   │   │   └── findings.txt
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_findings.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
│   ├── target6.com
│   │   ├── cves.txt
│   │   ├── dalfox.log
│   │   ├── dalfox.txt
│   │   ├── findings
│   │   ├── katana_result.txt
│   │   ├── link.txt
│   │   ├── nuclei_missing_headers.txt
│   │   ├── statics.txt
│   │   ├── takeover.txt
│   │   ├── targets_url.txt
│   │   └── technologies.txt
├── scope
│   ├── dns_ptr.txt
│   ├── live_target.txt
│   ├── subdomains.txt
│   └── target.txt
└── screenshot
    ├── gowitness.sqlite3
    ├── https---screeen1.jpeg
    └── https---screen2.jpeg

```
