#!/bin/bash

# Author: Felipe Molina (@felmoltor)
# Date: 05/09/2013
# Summary: Get a list of IPs and check for:
#	* Minimum Key Lenght accepted by the server (>= 128 bits)
#	* SSLv2 accepted
#   * MAC signed with MD5
#   * CBC ciphers with SSLv3 or TLSv1

# TODO: Set a timeout for sslscan to complete

###########
# GLOBALS #
###########

NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2; tput bold)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)

FORCE_SCAN=0 # If there is already a result file for this IP, scan it again
RESULTS_DIR="results"
PING_FIRST=1 # Ping the IP before sslscan, but only if there is no previous file output of sslscan
SCANTIMEOUT=60

#############
# FUNCTIONS #
#############

function red() 
{
    echo -e "$RED$*$NORMAL"
}

function green() 
{
    echo -e "$GREEN$*$NORMAL"
}

function yellow() {
    echo -e "$YELLOW$*$NORMAL"
}

###################

function supportTLSv11() {
    local ip=$1
    local port=$2
    # This function was extracted from TLSSLed_v1.3 (recognition to Taddong http://www.taddong.com/tools/TLSSLed_v1.3.sh)
    OUTPUT_TLS1_1=$((echo Q; sleep 1) | openssl s_client -tls1_1 -connect $ip:$port 2>&1)

    if grep -q DONE <<<$OUTPUT_TLS1_1; then
        return 1
    elif grep -q "wrong version number" <<<$OUTPUT_TLS1_1; then
        return 0
    elif grep -q "ssl handshake failure" <<<$OUTPUT_TLS1_1; then
        return 0
    elif grep -q "unknown option" <<<$OUTPUT_TLS1_1; then
        return -1
    else
        return -1
    fi
}

###################

function supportTLSv12() {
    local ip=$1
    local port=$2
    # This function was extracted from TLSSLed_v1.3 (recognition to Taddong http://www.taddong.com/tools/TLSSLed_v1.3.sh)
    OUTPUT_TLS1_2=$((echo Q; sleep 1) | openssl s_client -tls1_2 -connect $ip:$port 2>&1)

    if grep -q DONE <<<$OUTPUT_TLS1_2; then
        return 1
    elif grep -q "wrong version number" <<<$OUTPUT_TLS1_2; then
        return 0
    elif grep -q "ssl handshake failure" <<<$OUTPUT_TLS1_2; then
        return 0
    elif grep -q "unknown option" <<<$OUTPUT_TLS1_2; then
        return -1
    else
        return -1
    fi
}

###################

function containsElement () 
{
    local e
    for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 1; done
    return 0
}

###################

function hasMinimumLength()
{
    if [[ $2 -lt $1 ]]
    then
        return 0
    else
        return 1
    fi
}

###################

function searchCBCMethod()
{
    local cbc_enabled=0
    for method in $@
    do
        IFS="-"
        for chunk in $method
        do
            if [[ ($chunk == "CBC") || ($chunk == "CBC3") ]]
            then
                cbc_enabled=1
            fi
        done
        unset IFS
    done
    return $cbc_enabled
}

###################

function searchMD5Algorithms() 
{
    local md5_mac=0
    for method in $@
    do
        IFS="-"
        for chunk in $method
        do
            if [[ $chunk == "MD5" ]]
            then
                md5_mac=1
            fi
        done
        unset IFS
    done
    return $md5_mac
   
}

###################

function isCommandAvailable {
    type -P $1 >/dev/null 2>&1 || { echo >&2 "Program '$1' is not installed. Please install it before executing this script"; exit 1; }
    return 0
}

###################

function isValidIP()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

###################

function isHostAvailable {
    local available
    error=0

    pingresponse=$( ping -c 2 $1 -q 2> /dev/null )
    pingError=$?
    if [[ $pingError != 0 || ${#pingresponse} == 0 ]];then
        error=1
    else
        packetLoss=$( echo $pingresponse | tail -n2 | head -n1 | awk -F, '{print $3}' | awk -F% '{print $1}' | tr -d ' ' )
        if [[ $packetLoss != '0' ]];then
            error=2
        fi  
    fi
    return $error
}

function extractSubjectFromFile {
    sslOutputFile=$1
    local subject=""
    if [[ -f $sslOutputFile ]]; then
        subject=$(grep -E '<subject>.*<\/subject>' $sslOutputFile | sed -r 's/<subject>(.*)<\/subject>/\1/g')
    fi
    echo $subject
}

function extractCNFromSubject {
    subject=$1

}

function extractIssuerFromFile {
    sslOutputFile=$1
    local issuer=""
    if [[ -f $sslOutputFile ]]; then
        issuer=$(grep -E '<issuer>.*<\/issuer>' $sslOutputFile | sed -r 's/<issuer>(.*)<\/issuer>/\1/g')
    fi
    echo $issuer
}

function extractVersionFromFile {
    sslOutputFile=$1
    local version=""
    if [[ -f $sslOutputFile ]]; then
        version=$(grep -E '<version>.*<\/version>' $sslOutputFile | sed -r 's/<version>(.*)<\/version>/\1/g')
    fi
    echo $version
}


function extractNotValidAfterFromFile {
    sslOutputFile=$1
    local nafter=""
    if [[ -f $sslOutputFile ]]; then
        nafter=$(grep -E '<not-valid-after>.*<\/not-valid-after>' $sslOutputFile | sed -r 's/<not-valid-after>(.*)<\/not-valid-after>/\1/g')
    fi
    echo $nafter
}

function extractNotValidBeforeFromFile {
    sslOutputFile=$1
    local nbefore=""
    if [[ -f $sslOutputFile ]]; then
        nbefore=$(grep -E '<not-valid-before>.*<\/not-valid-before>' $sslOutputFile | sed -r 's/<not-valid-before>(.*)<\/not-valid-before>/\1/g')
    fi
    echo $nbefore
}

function extractSigAlgorithmFromFile {
    sslOutputFile=$1
    local sigalg=""
    if [[ -f $sslOutputFile ]]; then
        sigalg=$(grep -E '<signature-algorithm>.*<\/signature-algorithm>' $sslOutputFile | sed -r 's/<signature-algorithm>(.*)<\/signature-algorithm>/\1/g')
    fi
    echo $sigalg
}


function extractPKAlgorithmFromFile {
    sslOutputFile=$1
    local pkalg=""
    if [[ -f $sslOutputFile ]]; then
        pkalg=$(grep -E '<pk-algorithm>.*<\/pk-algorithm>' $sslOutputFile | sed -r 's/<pk-algorithm>(.*)<\/pk-algorithm>/\1/g')
    fi
    echo $pkalg
}

function extractPKLengthFromFile {
    sslOutputFile=$1
    local pklen=""
    if [[ -f $sslOutputFile ]]; then
        pklen=$(grep -E '<pk error=.+ type=.+ bits=.+>' $sslOutputFile | sed -r 's/<pk error=.+ type=.+ bits=\"(.*)\">/\1/g')
    fi
    echo $pklen
}

function extractCNFromFile {
    sslOutputFile=$1
    cn=$(grep "<subject>" $sslOutputFile | awk -F"/" '{for (i=1;i<=NF;i++){ if ($i ~ /CN=(.*)[<|\/]?/) {print $i} }}' | cut -f2 -d= | tr -d '<')
    echo $cn
}

###################

##########
## MAIN ##
##########

isCommandAvailable "sslscan"
isCommandAvailable "cut"
isCommandAvailable "grep"
isCommandAvailable "timeout"

# Crea directorio de resultados si no existe ya
if [[ ! -d $RESULTS_DIR ]]
then
    mkdir -p $RESULTS_DIR
fi

# ARG 1
if [[ -f $1 ]]
then
	IP_FILE=$1
else
	echo "Usage: $0 <ip:port_list_file> [<output_file>]"
	exit 1
fi

# ARG 2
if [[ "$2" == "" ]]
then
    OUTPUT_FILE=$(date +%Y%m%d_%H%M%S_output.csv)
else
    OUTPUT_FILE=$2
fi

total_ips=$(wc -l $IP_FILE | cut -f1 -d' ')
cont=0

echo "IP;Risk Points;Key Len (>= 128 bits);SSLv2 Disabled;CBC Disabled (SSLv3,v2,TLSv1);MD5 based MAC;TLSv1.1;TLSv1.2;Cert. Autosigned;Cert. Valid Dates;Cert. Valid CN; Cert. Valid PK Length" > $OUTPUT_FILE

for ip in `cat $IP_FILE | tr -d ' '`
do
    cont=$(( cont+1 ))
    min_len_status="<NOT AVAILABLE>"
    sslv2_status="<NOT AVAILABLE>"
    beast_status="<NOT AVAILABLE>"
    md5_mac_status="<NOT AVAILABLE>"
    supportTLSv11="<NOT AVAILABLE>"
    supportTLSV12="<NOT AVAILABLE>"
    certIssuer="<NOT AVAILABLE>"
    certPKLength="<NOT AVAILABLE>"
    certPKAlgorithm="<NOT AVAILABLE>"
    certIssuer="<NOT AVAILABLE>"
    certSigAlgorithm="<NOT AVAILABLE>"
    certSubject="<NOT AVAILABLE>"
    certVersion="<NOT AVAILABLE>"
    certNotValidAfter="<NOT AVAILABLE>"
    certNotValidBefore="<NOT AVAILABLE>"
    certExpired="<NOT AVAILABLE>"
    certCorrectCN="<NOT AVAILABLE>"
    certCorrectPKLen="<NOT AVAILABLE>"
    certAutosigned="<NOT AVAILABLE>"
    beast_cbc=0
    hasSSLv2=0
    hasMinimum=1
    smalestkeylen=9999
    riskPoints=0

    echo 
	echo "Scanning $ip ($cont/$total_ips). Please wait..."
    # If this is not a commentary with a '#'
    if [[ ${ip:0:1} != "#" ]]
    then
        if [[ $PING_FIRST > 0 ]];then
            isHostAvailable $ip
            hostAvailable=$?
            if [[ $hostAvailable != 0 ]];then
                red "Either the domain doesn't exist or IP is not available now (ICMP echo used). Skipping '$ip'..."
                echo "$ip;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>" >> $OUTPUT_FILE
                continue
            fi
        fi # IF PING FIRST

        if [[ -f $RESULTS_DIR/$ip.out.xml ]]
        then
            if [[ $FORCE_SCAN == 1 ]]
            then
                timeout $SCANTIMEOUT sslscan --no-failed --xml=$RESULTS_DIR/$ip.out.xml $ip > /dev/null
            else
                echo "$ip has been previously scaned. Skipping this scan now."
            fi
        else
            timeout $SCANTIMEOUT sslscan --no-failed --xml=$RESULTS_DIR/$ip.out.xml $ip > /dev/null
        fi

        # If the scan timed out in $SCANTIMEOUT seconds we won t have a result file or it will have size 0
        if [[ -f $RESULTS_DIR/$ip.out.xml ]]; then
            size=$(ls -l $RESULTS_DIR/$ip.out.xml | awk '{print $5}')
            if [[ size -eq "0" ]]; then
                red "The program sslscan timed out (more than $SCANTIMEOUT). Skipping this IP..."
                echo "$ip;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>" >> $OUTPUT_FILE
                continue
            fi
        else
            red "The program sslscan couldn't create the result file. Skipping this IP..."
            echo "$ip;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>;<NOT AVAILABLE>" >> $OUTPUT_FILE
            continue
        fi

        # Retrieve certificate info
        certIssuer=$(extractIssuerFromFile $RESULTS_DIR/$ip.out.xml)
        certSubject=$(extractSubjectFromFile $RESULTS_DIR/$ip.out.xml)
        certNotValidAfter=$(extractNotValidAfterFromFile $RESULTS_DIR/$ip.out.xml)
        certNotValidBefore=$(extractNotValidBeforeFromFile $RESULTS_DIR/$ip.out.xml)
        certVersion=$(extractVersionFromFile $RESULTS_DIR/$ip.out.xml)
        certSigAlgorithm=$(extractSigAlgorithmFromFile  $RESULTS_DIR/$ip.out.xml)
        certPKAlgorithm=$(extractPKAlgorithmFromFile  $RESULTS_DIR/$ip.out.xml)
        certPKLength=$(extractPKLengthFromFile $RESULTS_DIR/$ip.out.xml)
        certCN=$(extractCNFromFile $RESULTS_DIR/$ip.out.xml)

        echo "Certificate Issuer: $certIssuer"
        echo "Certificat Subject: $certSubject"
        echo "Certificate Version: $certVersion"
        echo "Signature Algorithm: $certSigAlgorithm"
        echo "Public Key Algorithm: $certPKAlgorithm"
        echo "Public Key Length: $certPKLength"

        dafter=$(date --date="$certNotValidAfter" +%s)
        dbefore=$(date --date="$certNotValidBefore" +%s)
        today=$(date +%s)
        if [[ $today > $dafter ]]; then
            certExpired="FAIL"
            riskPoints=$(($riskPoints + 1))
            red "The certificate dates are $certExpired (Not Valid After $certNotValidAfter, Not Valid Before $certNotValidBefore)"
        elif [[ $today < $dbefore ]]; then
            certExpired="FAIL"
            riskPoints=$(($riskPoints + 1))
            red "The certificate dates are $certExpired (Not Valid After $certNotValidAfter, Not Valid Before $certNotValidBefore)"
        else
            certExpired="OK"
            green "The certificate dates are $certExpired (Not Valid After $certNotValidAfter, Not Valid Before $certNotValidBefore)"
        fi
   
        if [[ $certIssuer = $certSubject ]]; then
            certAutosigned="FAIL"
            riskPoints=$(($riskPoints + 1))
            red "This certificate is autosigned"
        else
            certAutosigned="OK"
        fi
        
        if [[ $certCN = $ip ]]; then
            certCorrectCN="OK"
            green "Certificate CN agree with the visited address ($certCN == $ip)"
        else
            certCorrectCN="FAIL"
            riskPoints=$(($riskPoints + 1))
            red "Certificate CN does not agree with the visited address ($certCN != $ip)" 
        fi

        if [[ $certPKLength < 2048 ]]; then
            certCorrectPKLen="FAIL"
            riskPoints=$(($riskPoints + 1))
            red "Certificat Public Key length is smaller than 2048"
        else
            certCorrectPKLen="OK"
            green "Certificate Public Key length is 2048 or higher"
        fi
        # Seach for cipher protocols accepted
        ciphers=$(grep '<cipher status="accepted" sslversion="' $RESULTS_DIR/$ip.out.xml | cut -f5 -d' ' | cut -f2 -d= | tr -d '"' | sort -u )
        smalestkeylen=$(grep "<cipher status=\"accepted\" sslversion=\"" $RESULTS_DIR/$ip.out.xml | cut -f6 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u --numeric-sort | head -n1)

        # For each cipher, show the smaller key length accepted by the server
        for cipher in $ciphers
        do
            echo -n "Smaller key lengt for cipher '$cipher': "
            grep "<cipher status=\"accepted\" sslversion=\"$cipher" $RESULTS_DIR/$ip.out.xml | cut -f6 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u --numeric-sort | head -n1
            methods=$(grep "<cipher status=\"accepted\" sslversion=\"$cipher" $RESULTS_DIR/$ip.out.xml | cut -f7 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u)
            # If is TLSV1 or SSLv3 we shouldnt accept CBC ciphers
            if [[ ($cipher == "SSLv3") || ($cipher == "TLSv1") || ($cipher == "SSLv2") ]]
            then
                searchCBCMethod $methods
                beast_cbc=$? 
            fi
        done
        
        # Is SSLv2 enabled?
        containsElement "SSLv2" $ciphers
        hasSSLv2=$?
        if [[ $hasSSLv2 == 1 ]]
        then
            red "SSLv2 detected"
            riskPoints=$(($riskPoints + 1))
            sslv2_status="FAIL"
        else
            green "SSLv2 was not detected"
            sslv2_status="OK"
        fi

        # Is the keylength 128 bits or more?
        hasMinimumLength 128 $smalestkeylen
        hasMinimum=$?
        if [[ $hasMinimum == 0 ]]
        then
            red "The minimum length of cipher keys not correct ($smalestkeylen bits)"
            riskPoints=$(($riskPoints + 1))
            min_len_status="FAIL"
        else
            green "The minimum length of cipher keys is correct ($smalestkeylen bits)"
            min_len_status="OK"
        fi

        if [[ $beast_cbc == 1 ]]
        then
            red "This host is not protected against BEAST (Uses CBC/CBC3 with TLSv1 or SSLv2,v3)"
            riskPoints=$(($riskPoints + 1))
            beast_status="FAIL"
        else
            green "This host is protected against BEAST (Does not use CBC/CBC3 with TLSv1 or SSLv2,v3)"
            beast_status="OK"
        fi

        searchMD5Algorithms $methods
        weakMACAlgorithm=$?
        if [[ $weakMACAlgorithm == 1 ]]
        then
            red "This host has a weak MAC algorithm (Using MD5)"
            riskPoints=$(($riskPoints + 1))
            md5_mac_status="FAIL"
        else
            green "This hosts hasn't a weak MAC algorithm (Not using MD5)"
            md5_mac_status="OK"
        fi
 
        # Check for TLSv1.1 and TLSv1.2
        supportTLSv11 $ip 443
        s=$?
        if [[ $s == 1 ]]; then
            green "Supports TLSv1.1"
            supportTLSv11="SUPPORTED"
        elif [[ $s == 0 ]]; then
            supportTLSv11="NOT SUPPORTED"
            riskPoints=$(($riskPoints + 1))
            red "Does NOT support TLSv1.1"
        else
            supportTLSv11="NOT CHECKED"
            yellow "TLSv1.1 is not present in your OpenSSL and cannot be checked"
        fi
        supportTLSv12 $ip 443
        s=$?
        if [[ $s == 1 ]]; then
            green "Supports TLSv1.2"
            supportTLSv12="SUPPORTED"
        elif [[ $s == 0 ]]; then
            supportTLSv12="NOT SUPPORTED"
            riskPoints=$(($riskPoints + 1))
            red "Does NOT support TLSv1.2"
        else
            supportTLSv12="NOT CHECKED"
            yellow "TLSv1.2 is not present in your OpenSSL and cannot be checked"
        fi

        echo "$ip;$riskPoints;$min_len_status;$sslv2_status;$beast_status;$md5_mac_status;$supportTLSv11;$supportTLSv12;$certAutosigned;$certExpired;$certCorrectCN;$certCorrectPKLen" >> $OUTPUT_FILE

       
    else # Is not a commentary with "#"
        echo "Skipping commentary $ip"
    fi # Is not a commentary
    
done
