#!/bin/bash

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latestsudo mv ~/go/bin/nuclei /usr/local/bin/
go install github.com/projectdiscovery/katana/cmd/katana@latestsudo mv ~/go/bin/katana /usr/local/bin/
go install github.com/hahwul/dalfox/v2@latestsudo mv ~/go/bin/dalfox /usr/local/bin/
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latestsudo mv ~/go/bin/httpx /usr/local/bin/
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latestsudo mv ~/go/bin/dnsx /usr/local/bin/
go install github.com/tomnomnom/assetfinder@latestsudo mv ~/go/bin/assetfinder /usr/local/bin/
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latestsudo mv ~/go/bin/subfinder /usr/local/bin/
go install github.com/sensepost/gowitness@latestsudo mv ~/go/bin/gowitness /usr/local/bin/

curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/local/findomain
rm -rf findomain
rm findomain-linux.zip

git clone https://github.com/0xKayala/ParamSpider /opt/ParamSpider
cd /opt/ParamSpider
sudo python3 -m pip install -r requirements.txt
ln -s /opt/ParamSpider/paramspider.py /usr/local/bin/paramspider
cd -
sudo git clone https://github.com/maurosoria/dirsearch.git --depth 1 /opt/dirsearch
cd /opt/dirsearch
sudo python3 -m pip install -r requirements.txt
ln -s /opt/ParamSpider/dirsearch.py /usr/local/bin/dirsearch
cd -

git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
python3 -m pip install -r requirements.txt
sudo mv SecretFinder.py /usr/local/bin/secretfinder
cd -rm -rf secretfinder
wget https://raw.githubusercontent.com/w9w/JSA/main/templates/credentials-disclosure-all.yaml
wget https://raw.githubusercontent.com/w9w/JSA/main/templates/some-PIIs.yamlmkdir ~/nuclei-templates/JSA
mv some-PIIs.yaml ~/nuclei-templates/JSA/
mv credentials-disclosure-all.yaml ~/nuclei-templates/JSA/
