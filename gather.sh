#!/bin/bash

CYAN="\e[0;36m"
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW="\033[0;33m"
NC='\033[0m'

echo -e "${CYAN}  _______      ___   .___________. __    __   _______ .______      ${NC}";
echo -e "${CYAN} /  _____|    /   \  |           ||  |  |  | |   ____||   _  \     ${NC}";
echo -e "${CYAN}|  |  __     /  ^  \ \`---|  |----\`|  |__|  | |  |__   |  |_)  |    ${NC}";
echo -e "${CYAN}|  | |_ |   /  /_\  \    |  |     |   __   | |   __|  |      /     ${NC}";
echo -e "${CYAN}|  |__| |  /  _____  \   |  |     |  |  |  | |  |____ |  |\  \----.${NC}";
echo -e "${CYAN} \______| /__/     \__\  |__|     |__|  |__| |_______|| _| \`._____|${NC}";
echo -e "${CYAN}                                                                   ${NC}";



#nmap_path
#katana_path
#nuclei_path
#dalfox_path
#dirsearch_path
#httpx_path
#dnsx_path
#assetfinder_path
#findomain_path
#subfinder_path
#paramspider_path
#secretfinder_path
#gowitness_path
#linkfinder_path
#misconfig-mapper_path
#intercatsh-client_path


dns_result=$(pwd)/dns_ptr.txt  # domain retrived from IP
katana_result=$(pwd)/katana_result.txt # katana static finding
targets=$(pwd)/target.txt # working file
live_target=$(pwd)/live_target.txt
domains_tmp=$(pwd)/domains.tmp # working file for domain
subdomains=$(pwd)/subdomains.txt # list of valif subdomain
nuclei_vuln=$(pwd)/nuclei_vuln.txt
technologies=$(pwd)/technologies.txt
cves=$(pwd)/cves.txt
targets_url=$(pwd)/targets_url.txt # urls with param
dalfox_out=$(pwd)/dalfox.txt
dalfox_blind_out=$(pwd)/dalfox_blind.txt
statics=$(pwd)/statics.txt
findings=$(pwd)/findings
nuclei_findings=$(pwd)/nuclei_findings.txt
nuclei_headers=$(pwd)/nuclei_missing_headers.txt
dirsearch=$(pwd)/dirsearch.txt
takeover=$(pwd)/takeover.txt
log=$(pwd)/log.log
dalfox_log=$(pwd)/dalfox.log
link=$(pwd)/link.txt
mapping=$(pwd)/mapping.txt
domains=$(pwd)/domains.txt
interact_session=$(pwd)/interact_session.txt
interact_output=$(pwd)/interact_output.txt
response=$(pwd)/responses
js=$(pwd)/js

s_flag=false # flag for search subdomains
m_flag=false # flag for use mapper
b_flag=false # flag for blind XSS


usage() {
  echo -e "Use -i for IP/CIDR or -d for file with domains\n -a for active scan (optional)\n -s for enable subdomain search with domain" 1>&2
}

exit_abnormal() {
  usage
  exit 1
}


check_input_type() {
    local input=$1
     # check single IP
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "IP"
    # Check CIDR
    elif [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        echo "CIDR"
    else
        exit_abnormal
    fi
}

check_ip_equality() {
    local ip1=$1
    local ip2=$2

    if [[ "$ip1" == "$ip2" ]]; then
        return 0  
    else
        return 1  
    fi
}


check_ip_in_cidr() {
    local ip=$1
    local cidr=$2

    network=$(echo "$cidr" | cut -d "/" -f 1)
    netmask=$(echo "$cidr" | cut -d "/" -f 2)

    IFS=. read -r ip1 ip2 ip3 ip4 <<< "$ip"
    IFS=. read -r net1 net2 net3 net4 <<< "$network"

    net_int=$(( (net1 << 24) + (net2 << 16) + (net3 << 8) + net4 ))

    ip_int=$(( (ip1 << 24) + (ip2 << 16) + (ip3 << 8) + ip4 ))

    mask=$(( (1 << 32) - (1 << (32 - netmask)) ))


    if [ $((ip_int & mask)) -eq $((net_int & mask)) ]; then
        return 0
    else
        return 1
    fi
}



check_scope() {
    local result_tmp=$(pwd)/result.tmp 
    local temp=$(pwd)/temp.tmp
    
    echo -e "${YELLOW}[-] Checking the scope${NC}"
    if [ -n "$ip" ]; then
        sort -u $1 | dnsx -silent -a -resp -nc > $result_tmp

        input_type=$(check_input_type "$ip")
        case $input_type in
            "CIDR")
                while IFS= read -r line; do
                    ip_wk=$(echo -e "$line" | awk '{print $3}' | grep -oP '(?<=\[).*?(?=\])')
                    if check_ip_in_cidr "$ip_wk" "$ip"; then
                        echo $line | awk '{print $1}' >> $targets 
                    fi
                done < "$result_tmp"
                ;;
            "IP")
                while IFS= read -r line; do
                    ip_wk=$(echo -e "$line" | awk '{print $3}' | grep -oP '(?<=\[).*?(?=\])')
                    if check_ip_equality "$ip_wk" "$ip"; then
                        echo $line | awk '{print $1}' >> $targets 
                    fi
                done < "$result_tmp"
                ;;
            *)
                echo -e "${RED}Wrong IP: $ip_tmp${NC}"
                ;;
        esac
        rm $result_tmp
    else
        local valid_domains=()
        while IFS= read -r line; do
            valid_domains+=("$line")
        done <  "$(pwd)/$domain"


        while IFS= read -r domain_value; do
            found=false
            for valid_domain in "${valid_domains[@]}"; do
                if [[ "$domain_value" == *"$valid_domain" || "$domain_value" == "$valid_domain" || "$domain_value" == *".$valid_domain" ]]; then
                    found=true
                    break
                fi
            done

            if [ "$found" = true ]; then
                echo "$domain_value" >> $targets
            fi
        done < "$1"
    fi

    if [[ -s $targets ]]; then
        sort -u $targets > $temp && mv $temp $targets
    fi

    httpx -l $targets --silent  -sr -srd $response > $live_target 
    echo -e "${GREEN}[+] Scope checked${NC}"
}



nmap_check(){
    mkdir $(pwd)/nmap/
    local nmap_result=$(pwd)/nmap/all
    echo -e "${YELLOW}[-] Start NMAP enumeration${NC}"
    nmap -sC -sV $ip  -oA $nmap_result | grep -o 'DNS:[^,]*' | awk -F: '{print $2}'  | sort | uniq > $dns_result
    echo -e "${GREEN}[+] NMAP enumeration completed. Result saved in:${NC} ${CYAN}$nmap_result${NC}"
}


dns_enum() {
    echo -e "${YELLOW}[-] Start DNS enumeration${NC}"
    echo $ip| dnsx -silent -resp-only -ptr >> $dns_result 2>> $log
    if [ ! -s $dns_result ]; then
        echo -e "${GREEN}[+] DNS enumeration completed.${NC} ${RED}0 Results. Quitting.${NC}"
        exit 0
    else
        echo -e "${GREEN}[+] DNS enumeration completed. Result saved in:${NC} ${CYAN}$dns_result${NC}"
    fi
}

statics_enum() {
    echo -e "${YELLOW}[-] Start statics enumeration with Katana${NC}"
    katana -silent -list $live_target  -d 5 -jc -kf all -fx -xhr -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $katana_result 2>> $log
    urlfinder -silent -dL $live_target >> $katana_result 2>> $log
    echo -e "${GREEN}[+] Statics enumeration completed. Result saved in:${NC} ${CYAN} $katana_result${NC}"
    #echo -e "${YELLOW}[-] Recovering domains${NC}"
    #for url in $(cat $katana_result); do
	#    echo -e "$url" | grep -oP "(?<=://)([^/]+)" >> "$domains_tmp"
    #done
    
    #check_scope $domains_tmp
    #rm $domains_tmp
    #echo -e "${GREEN}[+] Domains recovered${NC}"
}


search_subdomain() {
    local sub1="$(pwd)/subdomains-1.txt"
    local sub2="$(pwd)/subdomains-2.txt" 
    local sub3="$(pwd)/subdomains-3.txt" 
    local tmp="$(pwd)/tmp.txt" 
    
    echo -e "${YELLOW}[-] Start finding subdomains${NC}"
    cat $dns_result >> $subdomains # need to check the IP for the resolved DNS
    cat $dns_result | assetfinder --subs-only | grep -v "[INF]"  > $sub1 2>> $log &
    findomain -q -f $dns_result > $sub2 2>> $log &
    subfinder -dL $dns_result -silent -all -nc > $sub3 2>> $log &

    wait
    echo -e "${YELLOW}[-] Merge of subdomains${NC}"
    cat $sub1 $sub2 $sub3 |alterx --silent -en > $tmp

    sort -u $tmp > $subdomains
    rm $tmp $(pwd)/subdomains-*
    check_scope $subdomains
    echo -e "${GREEN}[+] Subdomain enumeration completed. Result saved in:${NC} ${CYAN}$subdomains${NC}"
    echo -e "${GREEN}[+] Valid targets saved in:${NC} ${CYAN}$targets${NC}\n${GREEN}[+] Live targets saved in:${NC}${CYAN}$live_target${NC}"
}


retrive_params(){
    local temp=$(pwd)/temp.tmp
    echo -e "${YELLOW}[-] Start parameters discover${NC}"
    katana --silent -f qurl -iqp -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -list $live_target -fx > $targets_url
    paramspider -l $live_target   1>/dev/null 2>> $log 
    if [ -s "$(pwd)/results/" ]; then
        if [ "$(ls -A $(pwd)/results/)" ]; then
            cat $(pwd)/results/* >> $targets_url
            rm -rf $(pwd)/results
        fi
    fi
    echo -e "${GREEN}[+] Parameters discover completed. Results saved in:${NC}${CYAN}$targets_url${NC}"
}

nuclei_check() {
    echo -e "${YELLOW}[-] Start enumeration with Nuclei${NC}"
    nuclei --silent -ut >/dev/null
    nuclei --silent -fr -t technologies -l $live_target  > $technologies
    nuclei --silent -fr -t cves -l $live_target  > $cves
    # cat $targets | nuclei -as --silent > $nuclei_vuln # not work
    nuclei --silent  -dast -list $targets_url > $nuclei_vuln
    nuclei --silent -fr -id http-missing-security-headers -list $live_target > $nuclei_headers
    nuclei --silent -fr -t takeovers -list $live_target > $takeover
    echo -e "${GREEN}[+] Nuclei enumeration completed. Results saved in:${NC}${CYAN}\n$technologies\n$cves\n$nuclei_vuln\n${CYAN}\n$takeover\n$nuclei_headers\n${NC}"
}

dalfox_check(){
    if [[ -s $targets_url ]]; then
        echo -e "${YELLOW}[-] Start XSS check with Dalfox${NC}"
        dalfox file $targets_url --remote-payloads=portswigger,payloadbox --waf-evasion > $dalfox_out 2> $dalfox_log
        echo -e "${GREEN}[+] XSS completed. Results saved in:${NC}${CYAN}$dalfox_out${NC}"

        # ############################### TEST BLIND XSS ############################### #
        if [[ "$b_flag" = true ]]; then
            echo -e "${YELLOW}[-] Start XSS Blind check with Dalfox${NC}"
            interactsh-client -v -sf $interact_session > $interact_output 2>&1 &
            sleep 10
            local remote=$(cat $interact_output| sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep "\[INF\]" | awk 'NR==3' | cut -d " "  -f 2)
            echo $remote
            remote="http://$remote"
            echo $remote  
            dalfox file $targets_url --waf-evasion -b $remote > $dalfox_blind_out 2>> $dalfox_log
            echo -e "${GREEN}[+] XSS Blind completed. Results saved in:${NC}${CYAN}$dalfox_blind${NC}"
        fi
        # ############################### TEST BLIND XSS ############################### #
    else
        echo -e "${YELLOW}[-] Not valid urls found. Dalfox check skipped${NC}"
    fi
}

secret_check(){
    local temp=$(pwd)/temp.tmp
    echo -e "${YELLOW}[-] Start secrets finding${NC}"
    katana  -list $katana_result --silent -em js -d 5 -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg > $temp 
    sort -u $temp > $statics
    echo "" > $temp
    #httpx -l $statics --silent  -sr -srd $js
    for i in $(cat $katana_result );do
        python3 /opt/linkfinder.py -i $i -d -o cli | grep -v "Running against" | grep -v "^$" | grep -v "Invalid input defined or SSL error for:"  >>  $temp
    done
    sort -u $temp | grep -ivf clear-list.txt > $link
    echo "" > $temp
    # https://raw.githubusercontent.com/m4ll0k/SecretFinder/2c97c1607546c1f5618e829679182261f571a126/SecretFinder.py for  issue with -e flag
    
    if [[ -s $statics ]]; then
        mkdir $(pwd)/findings
        c=1
        for i in $(cat $statics);do  
            secretfinder -i $i -g 'jquery;bootstrap;api.google.com' -o cli > $(pwd)/findings/$c.txt
            ((c=c+1))
        done
	cat  $(pwd)/findings/* >> $temp
 	sort -u $temp > $findings
        echo -e "${GREEN}[+] Secret findings completed. Results saved in the directory ${NC}${CYAN}$(pwd)/findings/${NC} unique result saved in: ${NC}${CYAN}$findings${NC}"
    else
        echo -e "${YELLOW}[-] Statics not found. SecretFinder skipped${NC}"
    fi
    rm $temp
    echo -e "${YELLOW}[-] Start secrets finding with nuclei ${NC}"
    nuclei -t javascript/enumeration -l $live_target --silent > $nuclei_findings
    #https://github.com/w9w/JSA/tree/main/templates
    if [[ -n "$domain" ]];then
        nuclei -t JSA -l $live_target --silent | grep "PII" | grep -v "\"\""  >> $nuclei_findings
    else	
        nuclei -t JSA -l $targets --silent | grep "PII" | grep -v "\"\""  >> $nuclei_findings
    fi
    echo -e "${GREEN}[+] Secret findings completed. Results saved in:${NC}${CYAN}$nuclei_findings${NC} ${GREEN}and${NC} ${CYAN}$link${NC}"
}



dir_search() {
    echo -e "${YELLOW}[-] Start directory enumeration${NC}"
    if [ -n "$domain" ];then
    	if [[ "$s_flag" = false ]]; then
       		httpx -l $targets --silent -sr -srd $response > $live_target
    	fi
        dirsearch -l $live_target  --crawl -r -q -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --format plain -o $dirsearch 1>/dev/null 2>/dev/null
    else
        dirsearch --nmap-report nmap/all.xml  --crawl -r -q -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,log,xml,js,json --format plain -o $dirsearch 1>/dev/null 2>/dev/null
    fi
    echo -e "${GREEN}[+] Directory enumeration completed. Results saved in:${NC}${CYAN}$dirsearch${NC}"
}

screenshot() {
    echo -e "${YELLOW}[-] Take screenshots ${NC}"
    #if [ -n "$domain" ]; then
    #    gowitness file -f $live_target --screenshot-fullpage -q 2>$log
    if [ -n "$ip" ]; then
        gowitness scan nmap -f nmap/all.xml -o --service-contains http --screenshot-fullpage -q 2>>$log
    else
        gowitness scan file -f $live_target --screenshot-fullpage -q 2>>$log
    fi
    echo -e "${GREEN}[+] Screenshot taken. Results saved in:${NC}${CYAN}$(pwd)${NC}\n${YELLOW}Run ${CYAN}gowitness report server${NC}${YELLOW} for check the report${NC}"
}


mapper() {
    echo -e "${YELLOW}[-] Mapping vulnerabilities ${NC}"
    awk -F'.' '{print $(NF-1)}' $(cat $target | httpx --silent ) | sort | uniq > $domains
    for d in $(cat $domains);do
        misconfig-mapper -target $d -service "*"  | grep -v "\[-\]" >> $mapping
    done;
    echo -e "${GREEN}[+] Mapping completed. Results saved in:${NC}${CYAN}$mapping${NC}"
}


passive() {
    date >> $log
    check_input_type $ip >/dev/null
    echo -e "${GREEN}[+] Working for the IP/CIDR:${NC} ${CYAN}$ip${NC}"
    echo -e "${GREEN}[+] The output will be saved in the directory:${NC}${CYAN}$(pwd)${NC}"
    nmap_check
    dns_enum
    search_subdomain
    statics_enum
    #if [ ! -s $target ]; then
    #    echo -e "${GREEN}[+] DNS enumeration completed.${NC}${RED}0 Target. Quitting.${NC}"
    #    exit 0
    #fi
    screenshot
    secret_check
    echo -e "${GREEN}[+]Passive scans completed${NC}"
}


active() {
    retrive_params
    nuclei_check
    dalfox_check
    dir_search
    if [[ "$m_flag" = true ]]; then
    	mapper
    fi
    killall interactsh-client 2>/dev/null   # kill running interactsh at the end of full scan
    echo -e "${GREEN}[+] Active scans completed${NC}"
}


domain() {
    cat "$domain" > $dns_result
    if [[ "$s_flag" = true ]]; then
       search_subdomain
    else
        httpx -l "$domain" --silent -sr -srd $response > $live_target 
    fi
    statics_enum
    screenshot
    secret_check
}



while getopts ":i:d:asmb" options; do
  case "${options}" in
    i)
        ip=${OPTARG}
        ;;
    d)
        domain=${OPTARG}
        ;;
    a)
        a_flag=true
        ;;
    s)
        s_flag=true
        ;;
    m)
    	m_flag=true
    	;;
    b)
    	b_flag=true
    	;;
    :)
        echo -e "${GREEN}[!] Error: Option -$OPTARG requires an argument.${NC}" >&2
        exit_abnormal
        ;;
    *)
        exit_abnormal
        ;;
  esac
done


if [[ -z "$ip" && -z "$domain" ]]; then
  exit_abnormal
else
  if [[ -n "$ip" ]]; then
    passive
  fi

  if [[ -n "$domain" ]]; then
    domain
  fi

  if [[ "$a_flag" = true ]]; then
      active
  fi
  exit 0
fi
