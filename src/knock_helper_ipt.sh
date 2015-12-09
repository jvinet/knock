#!/bin/sh

# Original version to add non-duplicated rules by Greg Kuchyt (greg.kuchyt@gmail.com)
# Updated to handle deletes and be generic by Paul Rogers (paul.rogers@flumps.org)

SCRIPT_NAME=$(basename $0)

AWK="/bin/awk"
GREP="/bin/grep"
IPTABLES="/sbin/iptables"
SORT="/bin/sort"

COMMENT_APP="Append "
COMMENT_DEL="Delete "
COMMENT_INS="Insert "
COMMENT_DEFAULT="by knockd"

IPT_CHAIN="INPUT"
IPT_METHOD=""
IPT_COMMENT=""
IPT_SRC_IP=""
IPT_DST_PORT=""
IPT_PROTO="tcp"
IPT_RULE_TARGET="ACCEPT"

DRY_RUN=0
SEEN=0
VERBOSE=0

usage() {
	echo "Usage: $SCRIPT_NAME -a|-i|-x -f SRC_IP_ADDR -d DST_PORT [-p|-c|-m|-t|-h|-v]"
	echo "Options:"
	echo "-a|--append      Action: append a rule to NetFilter"
	echo "-i|--insert      Action: insert a rule to NetFiler"
	echo "-x|--delete      Action: delete a rule from NetFilter"
	echo "-f|--srcaddr     The source IP address to be used"
	echo "-d|--dstport     The destination port to be used in the rule"
	echo "-p|--proto       The protocol that the rule applies to; default: $IPT_PROTO"
	echo "-c|--chain       The NetFilter chain to apply the change to; default: $IPT_CHAIN"
	echo "-m|--comment     Overide default comment text: '$COMMENT_DEFAULT'"
	echo "-t|--test        Test run - don't actually perform an update to NetFilter"
	echo "-h|--help        Print this informational screen and exit"
	echo "-v|--verbose     Print verbose information about actions"
}

ARGS=$(getopt -o aixf:d:p:c:m::thv -l "append,insert,delete,srcaddr:,dstport:,proto:,chain:,comment::,test,help,verbose" -n $SCRIPT_NAME -- "$@")

if [ $? -ne 0 ];
then
        echo "$SCRIPT_NAME - Error! Invalid arguments"
        usage
        exit 1
fi

eval set -- "$ARGS"

while true; do
        case "$1" in
		-a|--append)
			IPT_METHOD="-A"
			shift;
		;;
		-x|--delete)
			IPT_METHOD="-D"
			shift;
		;;
		-i|--insert)
			IPT_METHOD="-I"
			shift;
		;;
		-f|--srcaddr)
			IPT_SRC_IP=$2
			shift 2;
		;;
		-d|--dstport)
			IPT_DST_PORT=$2
			shift 2;
		;;
		-p|--proto)
			IPT_PROTO=$2
			shift 2;
		;;
		-c|--chain)
			IPT_CHAIN=$2
			shift 2;
		;;
		-m|--comment)
			case "$2" in
				"")
					IPT_COMMENT=$COMMENT_DEFAULT;
					shift 2;;
				*)
					IPT_COMMENT=$2;
					shift 2 ;;
			esac
		;;
		-t|--test)
			DRY_RUN=1
                        shift;
                ;;
		-h|--help)
			usage
			shift;
			exit
		;;
		-v|--verbose)
			VERBOSE=1
			shift;
		;;
                --)
                        shift;
                        break;
                ;;
        esac
done

# Begin sanity checks
if [ -z "$IPT_SRC_IP" ]; then
	echo "$SCRIPT_NAME - Error! Source IP address required"
	usage
	exit 1
fi

if [ -z "$IPT_DST_PORT" ]; then
	echo "$SCRIPT_NAME - Error! Destination port required"
	usage
	exit 1
fi

if [ -z "$IPT_METHOD" ]; then
	echo "$SCRIPT_NAME - Error! Valid action option not specified"
fi

case "$IPT_METHOD" in
	-A)
		IPT_COMMENT="$COMMENT_APP $IPT_COMMENT"
		;;
	-I)
		IPT_COMMENT="$COMMENT_INS $IPT_COMMENT"
		;;
	-D)
		IPT_COMMENT="$COMMENT_DEL $IPT_COMMENT"
		;;
esac

if [ "$VERBOSE" -eq 1 ]; then
	echo "$SCRIPT_NAME - Testing rule"
	echo "$SCRIPT_NAME - action: $IPT_METHOD _ src: $IPT_SRC_IP _ dstport: $IPT_DST_PORT _ proto: $IPT_PROTO _ chain: $IPT_CHAIN _ comment: $IPT_COMMENT"
fi

COMMENT=""
if [ -n "$IPT_COMMENT" ]; then
	COMMENT="-m comment --comment '$IPT_COMMENT'"
fi

$IPTABLES -L $IPT_CHAIN &> /dev/null
if [ 0 -ne "$?" ]; then
	echo "$SCRIPT_NAME - Error: $IPT_CHAIN is not a valid NetFilter chain"
	exit
fi
# End sanity checks

# Dupe checking
for IP in `$IPTABLES -n -L $IPT_CHAIN | $GREP $IPT_RULE_TARGET | $AWK '{print $4}' | $SORT -u`;
do
	if [ "$VERBOSE" -eq 1 ]; then
		echo "$SCRIPT_NAME - $IP"
	fi

	if [ "$IPT_SRC_IP" == "$IP" ]; then
		SEEN=1
	fi
done

if [ "$VERBOSE" -eq 1 ]; then
	echo "$SCRIPT_NAME - Seen: $SEEN"
fi


if [ "$SEEN" -eq 0 ]; then
	if [ "$VERBOSE" -eq 1 ]; then
		echo "$SCRIPT_NAME - $IPT_COMMENT"
		echo $IPTABLES $IPT_METHOD $IPT_CHAIN -s $IPT_SRC_IP -p $IPT_PROTO --dport $IPT_DST_PORT -j $IPT_RULE_TARGET $COMMENT
	fi

	if [ "$DRY_RUN" -eq 0 ]; then
		eval $IPTABLES $IPT_METHOD $IPT_CHAIN -s $IPT_SRC_IP -p $IPT_PROTO --dport $IPT_DST_PORT -j $IPT_RULE_TARGET $COMMENT
	fi
fi