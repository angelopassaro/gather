

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo mv ~/go/bin/nuclei /usr/local/bin/
go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo mv ~/go/bin/katana /usr/local/bin/
go install github.com/hahwul/dalfox/v2@latest
sudo mv ~/go/bin/dalfox /usr/local/bin/
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo mv ~/go/bin/httpx /usr/local/bin/
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo mv ~/go/bin/dnsx /usr/local/bin/
go install github.com/tomnomnom/assetfinder@latest
sudo mv ~/go/bin/assetfinder /usr/local/bin/
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo mv ~/go/bin/subfinder /usr/local/bin/
go install github.com/sensepost/gowitness@latest
sudo mv ~/go/bin/gowitness /usr/local/bin/


curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/bin/local/findomain
rm -rf findomain
rm findomain-linux.zip


sudo git clone https://github.com/devanshbatham/paramspider /opt/paramspider
cd /opt/paramspider
sudo python3 -m pip install .
sudo rm -rf /opt/paramspider
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
cd -
rm -rf secretfinder

wget https://raw.githubusercontent.com/w9w/JSA/main/templates/credentials-disclosure-all.yaml
wget https://raw.githubusercontent.com/w9w/JSA/main/templates/some-PIIs.yaml
mkdir ~/nuclei-templates/JSA
mv some-PIIs.yaml ~/nuclei-templates/JSA/
mv credentials-disclosure-all.yaml ~/nuclei-templates/JSA/
