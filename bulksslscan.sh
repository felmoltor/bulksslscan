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
PING_FIRST=0 # TODO: Ping the IP before sslscan, but only if there is no previous file output of sslscan

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

function containsElement () 
{
    local e
    for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 1; done
    return 0
}

function hasMinimumLength()
{
    if [[ $2 -lt $1 ]]
    then
        return 0
    else
        return 1
    fi
}

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

function isCommandAvailable {
    type -P $1 >/dev/null 2>&1 || { echo >&2 "Program '$1' is not installed. Please install it before executing this script"; exit 1; }
    return 0
}

function isHostAvailable {
    local available
    available=0
    packetLoss=$(ping -c 3 $1 | tail -n2 | head -n1 | awk -F, '{print $3}' | tr -d ' ')

    if [[ $packetLoss == "0%" ]]
    then
        available=1
    fi

    return $available
}

###################

##########
## MAIN ##
##########

isCommandAvailable "sslscan"
#isCommandAvailable "timeout"
isCommandAvailable "cut"
isCommandAvailable "grep"

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
    OUTPUT_FILE="results.csv"
else
    OUTPUT_FILE=$2
fi

hasSSLv2=0
hasMinimum=1
smalestkeylen=9999
total_ips=$(wc -l $IP_FILE | cut -f1 -d' ')
cont=1
beast_cbc=0
min_len_status="<NOT AVAILABLE>"
sslv2_status="<NOT AVAILABLE>"
beast_status="<NOT AVAILABLE>"
md5_mac_status="<NOT AVAILABLE>"

echo "IP;Key Len (>= 128 bits);SSLv2 Disabled;CBC Disabled (SSLv3,v2,TLSv1);MD5 based MAC" > $OUTPUT_FILE

for ip in `cat $IP_FILE | tr -d ' '`
do
    echo 
	echo "Scanning $ip ($cont/$total_ips). Please wait..."
    # If this is not a commentary with a '#'
    if [[ ${ip:0:1} != "#" ]]
    then
        #if [[ -f $RESULTS_DIR/$ip.out.xml ]]
        # then
        #    hostAvailable=1
            # Check if is available by pinging this IP
        #    if [[ $PING_FIST == 1 ]]
        #    then
        #        ip_only=$(echo $ip | sed 's/:.*//g')
        #        echo "Pinging to $ip_only. Please wait..."
        #        hostAvailable=$(isHostAvailable $ip_only)
        #    fi

        if [[ -f $RESULTS_DIR/$ip.out.xml ]]
        then
            if [[ $FORCE_SCAN == 1 ]]
            then
                sslscan --no-failed --xml=$RESULTS_DIR/$ip.out.xml $ip > /dev/null
            else
                echo "$ip has been previously scaned. Skipping this scan now."
            fi
        else
            sslscan --no-failed --xml=$RESULTS_DIR/$ip.out.xml $ip > /dev/null
        fi
        
        # Seach for cipher protocols accepted
        ciphers=$(grep '<cipher status="accepted" sslversion="' $RESULTS_DIR/$ip.out.xml | cut -f5 -d' ' | cut -f2 -d= | tr -d '"' | sort -u )
        smalestkeylen=$(grep "<cipher status=\"accepted\" sslversion=\"" $RESULTS_DIR/$ip.out.xml | cut -f6 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u --numeric-sort | head -n1)

        # For each cipher, show the smaller key length accepted by the server
        for cipher in $ciphers
        do
            echo -n " Smaller key lengt for cipher '$cipher': "
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
            min_len_status="FAIL"
        else
            green "The minimum length of cipher keys is correct ($smalestkeylen bits)"
            min_len_status="OK"
        fi

        if [[ $beast_cbc == 1 ]]
        then
            red "This host is not protected against BEAST (Uses CBC/CBC3 with TLSv1 or SSLv2,v3)"
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
            md5_mac_status="FAIL"
        else
            green "This hosts hasn't a weak MAC algorithm (Not using MD5)"
            md5_mac_status="OK"
        fi

        echo "$ip;$min_len_status;$sslv2_status;$beast_status;$md5_mac_status" >> $OUTPUT_FILE
        
        #else
        #    echo "IP $ip is not available now or is filtering out ping requests. Skiping."
        #fi # if $hostAvailable
        
    else # Is not a commentary with "#"
        echo "Skipping commentary $ip"
    fi # Is not a commentary
    
    cont=$(( cont+1 ))
done


