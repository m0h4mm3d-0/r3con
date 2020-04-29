#!bin/bash
#by @m4hunt3r:Mohamede-Addar &&  @safa7:Sohail-Bzioui

RED='\033[0;31m'
NC='\033[0m'

###sublist3r
echo "{+} starting sublist3r"
sublist3r -d $1 -v -o domains.txt

###subfinder
echo "{+} starting subfinder"
subfinder -d $1 | tee -a domains.txt

###assetfinder
echo "{+} starting assetfinder"
assetfinder --subs-only $1 | tee -a domains.txt

###amass
echo "{+} starting amass"
amass enum --passive -d $1 | tee -a domains.txt

###crt.sh
echo "{+} starting crt.sh"
curl -s https://crt.sh/\?q\=\%.$1\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | tee -a domains.txt

###rm duplicate (sub)domains
sort -u domains.txt -o domains.txt

###subjack
echo "{+} checking for subdomain takeover"
subjack -w domains.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 | tee -a sub-takeover.txt

###check alive domains
echo "checking for alive (sub)domains"
cat domains.txt | httprobe | tee -a alive.txt

###sorting headers and response body
mkdir headers
mkdir responsebody

CURRENT_PATH=$(pwd)

for x in $(cat alive.txt)
do
	NAME=$(echo $x | awk -F/ '{print $3}')
	curl -X GET -H "X-Forwarded-For: evil.com" $x -I > "$CURRENT_PATH/headers/$NAME"
	curl -s -X GET -H "X-Forwarded-For: evil.com" -L $x > "$CURRENT_PATH/responsebody/$NAME"
done

###collect javascript files
mkdir scripts
mkdir scriptsresponse

CUR_PATH=$(pwd)

for x in $(ls "$CUR_PATH/responsebody")
do
	printf "\n\n${RED}$x${NC}\n\n"
	END_POINTS=$(cat "$CUR_PATH/responsebody/$x" | grep -Eoi "src=\"[^>]+></script>" | cut -d '"' -f 2)
	for end_point in $END_POINTS
	do
		len=$(echo $end_point | grep "http" | wc -c)
		mkdir "scriptsresponse/$x/"
		URL=$end_point
		if [ $len == 0 ]
		then
			URL="https://$x$end_point"
		fi
		file=$(basename $end_point)
                curl -X GET $URL -L > "scriptsresponse/$x/$file"
		echo $URL >> "scripts/$x"
	done
done

###collect endpoints
mkdir endpoints

CUR_DIR=$(pwd)

for domain in $(ls scriptsresponse)
do
	mkdir endpoints/$domain
	for file in $(ls scriptsresponse/$domain)
	do
		ruby ~/relative-url-extractor/extract.rb scriptsresponse/$domain/$file >> endpoints/$domain/$file 
	done
done

###run aquatone
echo "{+} starting aquatone"
cat domains.txt | aquatone -http-timeout 10000 -scan-timeout 300 -out $1
