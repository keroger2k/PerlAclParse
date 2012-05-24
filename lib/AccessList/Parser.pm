package AccessList::Parser;

use 5.008008;
use strict;
use warnings;
use Carp;
use Parse::RecDescent;

our $VERSION = '0.05';

sub new {
	my ($class) = @_;
	my $self = { PARSER => undef, };
	bless $self, $class;
	$self->_init();
	return $self;
}

sub _init {
	my ($self) = @_;
	$self->{PARSER} = Parse::RecDescent->new( $self->_grammar() );
}

sub parse {
	my ( $self, $string ) = @_;
	defined ($string) or confess "blank line received";
	my $tree = $self->{PARSER}->startrule($string);
	defined($tree) or confess "unrecognized line\n";
	return $tree;
}

sub _grammar {
	my ($self) = @_;

	my $grammar = q{
<autotree>

startrule :
		access_list EOL
	|	acl_remark EOL
	|	<error>

#
# access-lists
#

access_list : acl_action

acl_remark :
		"remark" REMARKS

acl_action :
		ACTIONS acl_protocol

#
# protocol options
#

acl_protocol :
		PROTOCOL acl_src_ip

#
# access-list source IP addresses
#

acl_src_ip :
		address acl_dst_ip
	|	address acl_src_port

#
# access-list source ports
#

acl_src_port : 
		port acl_dst_ip

#
# access-list destination IP address
#

acl_dst_ip :
		address acl_dst_port
	|	address acl_options
	| 	IPRANGE

#
# access-list destination ports
#

acl_dst_port : 
		port acl_options
	|   acl_icmp_type acl_options

#
# icmp_types
#

acl_icmp_type :
	   ICMP_TYPE

#
# access-list options
#

acl_options :
		acl_logging
	|	EOL
	|	<error>

acl_logging :
	 	"log-input"
	
#
# IP address types
#
# "object" should be fine here because "object" can not  
# be used to specify ports 

address :
		"host" IPADDRESS
	|	"host" NAME
	|	IPNETWORK
	|	NAMED_NET
	|	ANY

#
# port types
#

port :
		port_eq
	|	port_range
	|	port_gt
	|	port_lt
	|	port_neq

port_eq :
	"eq" PORT_ID

port_range :
	"range" PORT_RANGE

port_gt :
	"gt" PORT_GT

port_lt :
	"lt" PORT_LT

port_neq :
	"neq" <error: neq is unsupported>

#
# Token Definitions
#

STRING :
		/\S+/

DIGIT :
		/\d+/

NAME :
		/((^|\s[a-zA-Z])(\.|[0-9a-zA-Z_-]+)+)/

RULE_REF :
		/\S+/

ANY:
		"any"

IPADDRESS :
		/((\d{1,3})((\.)(\d{1,3})){3})/

MASK :
		/(255|254|252|248|240|224|192|128|0)((\.)(255|254|252|248|240|224|192|128|0)){3}/

IPNETWORK :
		/((\d{1,3})((\.)(\d{1,3})){3}) ((255|254|252|248|240|224|192|128|0)((\.)(255|254|252|248|240|224|192|128|0)){3})/

IPRANGE :
		/((\d{1,3})((\.)(\d{1,3})){3}) ((\d{1,3})((\.)(\d{1,3})){3})/

NAMED_NET :
		/((^|\s[a-zA-Z])(\.|[0-9a-zA-Z_-]+)+) ((255|254|252|248|240|224|192|128|0)((\.)(255|254|252|248|240|224|192|128|0)){3})/

PROTOCOL :
		/\d+/ | "ah" | "eigrp" | "esp" | "gre" | "icmp" | "icmp6" | "igmp" 
	| "igrp" | "ip" | "ipinip" | "ipsec" | "nos" | "ospf" | "pcp" 
	| "pim" | "pptp" | "snp" | "tcp" | "udp"

GROUP_PROTOCOL :
		"tcp-udp" | "tcp" | "udp"

ICMP_TYPE : 
		/\d+/ | "alternate-address" | "conversion-error" | "echo-reply" | "echo"
	| "information-reply" | "information-request" | "mask-reply" | "mask-request"
	| "mobile-redirect" | "parameter-problem" | "redirect" | "router-advertisement"
	| "router-solicitation" | "source-quench" | "time-exceeded" | "timestamp-reply"
	| "timestamp-request" | "traceroute" | "unreachable"

PORT_ID :
		/\S+/

PORT_GT :
		/\S+/
{
	bless {__VALUE__=>"$item[1] 65535"}, $item[0]
}

PORT_LT :
		/\S+/
{
	bless {__VALUE__=>"1 $item[1]"}, $item[0]
}

PORT_RANGE :
		/\S+ \S+/

ACTIONS :
		"permit"
	|	"deny"

REMARKS :
		/.*$/

LOG_LEVEL :
		/\d+/ | "emergencies" | "alerts" | "critical" | "errors" 
	| "warnings" | "notifications" | "informational" | "debugging"
	| "disable"

EOL :
		/$/	
};

	return $grammar;
}

1;