#!/bin/bash

[ -z "$1" ] && { printf "\n[!] Usage: bash EnumX.sh example.com\n"; exit; }

#COLORS
BOLD="\e[1m"
NORMAL="\e[0m"
RED="\e[92m"
#--------------------------------------------------------------------------------------------------------------------
echo -e "${RED}[+]Start Subdomain Enumeretion"
#--------------------------------------------------------------------------------------------------------------------

#Assetfinder
echo -e "${RED}[+] Starting Assetfinder"
#--------------------------------------------------------------------------------------------------------------------
assetfinder --subs-only $1 |sort -u |tee assetfinder.txt
#--------------------------------------------------------------------------------------------------------------------
echo -e "${RED}[+] Some Free Apis to extract the subdomains"
#--------------------------------------------------------------------------------------------------------------------
curl --silent "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" > tmp.txt
curl --silent "https://api.hackertarget.com/hostsearch/?q=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://crt.sh/?q=%.$1" | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | grep -oP "\K.*\.$1" | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1"  >> tmp.txt
curl --silent "https://crt.sh/?q=%.%.$1" | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://crt.sh/?q=%.%.%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> tmp.txt
curl --silent "https://crt.sh/?q=%.%.%.%.$1" | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" |  sort -u >> tmp.txt
curl --silent "https://certspotter.com/api/v0/certs?domain=$1" | grep  -o '\[\".*\"\]' | sed -e 's/\[//g' | sed -e 's/\"//g' | sed -e 's/\]//g' | sed -e 's/\,/\n/g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://spyse.2com/target/domain/$1" | grep -E -o "button.*>.*\.$1\/button>" |  grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://tls.bufferover.run/dns?q=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://dns.bufferover.run/dns?q=.$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://urlscan.io/api/v1/search/?q=$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent -X POST "https://synapsint.com/report.php" -d "name=http%3A%2F%2F$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://jldc.me/anubis/subdomains/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> tmp.txt
curl --silent "https://sonar.omnisint.io/subdomains/$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
curl --silent "https://riddler.io/search/exportcsv?q=pld:$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> tmp.txt
#--------------------------------------------------------------------------------------------------------------------
cat tmp.txt | sed -e "s/\*\.$1//g" | sed -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u > allapis.txt
#--------------------------------------------------------------------------------------------------------------------

#GAU
echo -e "${RED}[+] Starting Gau"
gau -b jpg,png,gif -o gauurls.txt $1 

#waybackurls
echo -e "${RED}[+] Starting waybackurls"
waybackurls $1 | grep "=" >  wackbkurls.txt

#paramspider
echo -e "${RED}[+] Starting paramspider"
python3 ~/tools/ParamSpider/paramspider.py --domain $1 --exclude woff,css,js,png,svg,php,jpg --output paramurls.txt

#golinkfinder
echo -e "${RED}[+] Starting golinkfinder"
GoLinkFinder -d $1 -o golinkurls.txt

#sigurls
echo -e "${RED}[+] Starting singurlsfinder"
sigurlfind3r -d $1 -f ".(jpg|jpeg|gif|png|ico|css|eot|tif|tiff|ttf|woff|woff2)" -o sigurls.txt

#hakrawler
echo -e "${RED}[+] Starting hakrawler"
echo $1 | hakrawler > hakrawlerurls.txt

#parth
echo -e "${RED}[+] Starting parth"
python3 ~/tools/Parth-master/parth.py -t $1 -o parth.txt

#Sublist3r
echo -e "${RED}[+] Starting Sublist3r"
#--------------------------------------------------------------------------------------------------------------------
python ~/tools/Sublist3r/sublist3r.py -d $1 -o sublist3r.txt
#--------------------------------------------------------------------------------------------------------------------
#Subfinder
#go get -v github.com/projectdiscovery/subfinder/cmd/subfinder
echo -e "${RED}[+] Starting Subfinder "
#--------------------------------------------------------------------------------------------------------------------
subfinder -d  $1 |sort -u |tee subfinder.txt
#--------------------------------------------------------------------------------------------------------------------
#Amass
echo -e "${RED}[+] Starting Amass\n"
#--------------------------------------------------------------------------------------------------------------------
amass enum -d $1 --passive -o amass.txt
#--------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------
#Filtering
echo -e "${RED}[+] Starting Filtering\n"
#--------------------------------------------------------------------------------------------------------------------
cat sublist3r.txt assetfinder.txt subfinder.txt allapis.txt| sort -u |uniq -u| grep -v "*" |sort -u|tee Final-Subs.txt
#--------------------------------------------------------------------------------------------------------------------
#Httprobe
echo -e "${RED}[+] Starting Httpx\n"
#--------------------------------------------------------------------------------------------------------------------
cat Final-Subs.txt |sort -u |uniq -u|httpx -silent |tee $1-alive.txt
#--------------------------------------------------------------------------------------------------------------------
echo -e "${RED}[+]Start Subdomain Takeover Scan\n"
#--------------------------------------------------------------------------------------------------------------------
subzy -targets Final-Subs.txt -hide_fails --verify_ssl -concurrency 20 |sort -u|tee "subzy.txt"
#--------------------------------------------------------------------------------------------------------------------
echo -e "${RED}[+] DNSPROBE Start\n"
#--------------------------------------------------------------------------------------------------------------------
cat $1-alive.txt|dnsprobe -o $1-dnsprobe.txt
#getjs
echo -e "${RED}[+] Starting getjs"
cat  $1-alive.txt  | getJS > js.txt
#linkfinder
echo -e "${RED}[+] Starting linkfinder"
python3 ~/tools/LinkFinder/linkfinder.py  -i  js.txt  -o cli

#priotx
echo -e "${RED}[+] Starting priotx"
bash ~/tools/Pri0tx/priotx.sh $1-alive.txt  > priotx.txt 
#end-point-finder
echo -e "${RED}[+] Starting end-point-finder"
python ~/tools/EndPoint-Finder-master/EndPoint-Finder.py  -f js.txt

#--------------------------------------------------------------------------------------------------------------------
echo -e "${RED}[+]Finishing The Enumeration OR The Reconaisses\n"
#--------------------------------------------------------------------------------------------------------------------
rm sublist3r.txt assetfinder.txt subfinder.txt allapis.txt tmp.txt
#--------------------------------------------------------------------------------------------------------------------
