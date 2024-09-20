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
