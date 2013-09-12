#!/bin/bash

# Author: Felipe Molina
# Date: 05/09/2013
# Summary: Get a list of IPs and check for:
#	* Minimum Key Lenght
#	* Cypher suites accepted

###########
# GLOBALS #
###########

NORMAL=$(tput sgr0)
GREEN=$(tput setaf 2; tput bold)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)

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

function searchCBCMethod(){
    cbc_enabled=0
    for method in $@
    do
        IFS="-"
        for chunk in $method
        do
            if [[ $chunk == "CBC" ]]
            then
                cbc_enabled=1
            fi
        done
        unset IFS
    done
    return $cbc_enabled
}

###################

##########
## MAIN ##
##########

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


echo "IP;Key Len (>= 128 bits);SSLv2 Disabled;CBC Disabled (SSLv3,TLSv1)" > $OUTPUT_FILE

for ip in `cat $IP_FILE`
do
    echo 
	echo "Scanning $ip ($cont/$total_ips). Please wait..."
	# sslscan --no-failed --xml=results/$ip.out.xml $ip > /dev/null
	# Seach for cipher protocols accepted
	ciphers=$(grep '<cipher status="accepted" sslversion="' results/$ip.out.xml | cut -f5 -d' ' | cut -f2 -d= | tr -d '"' | sort -u )
    smalestkeylen=$(grep "<cipher status=\"accepted\" sslversion=\"" results/$ip.out.xml | cut -f6 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u --numeric-sort | head -n1)

	# For each cipher, show the smaller key length accepted by the server
	for cipher in $ciphers
	do
		# echo -n "Smaller key lengt for cipher '$cipher': "
		# grep "<cipher status=\"accepted\" sslversion=\"$cipher" results/$ip.out.xml | cut -f6 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u --numeric-sort | head -n1
        methods=$(grep "<cipher status=\"accepted\" sslversion=\"$cipher" results/$ip.out.xml | cut -f7 -d' ' | cut -f2 -d'=' | tr -d '"' | sort -u)
        # If is TLSV1 or SSLv3 we shouldnt accept CBC ciphers
        if [[ ($cipher == "SSLv3") || ($cipher == "TLSv1") ]]
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
        red "This host is not protected against BEAST (Uses CBC with TLSv1 or SSLv3)"
        beast_status="FAIL"
    else
        green "This host is protected against BEAST (Does not use CBC with TLSv1 or SSLv3)"
        beast_status="OK"
    fi
	
    cont=$(( cont+1 ))

    echo "$ip;$min_len_status;$sslv2_status;$beast_status" >> $OUTPUT_FILE
done


