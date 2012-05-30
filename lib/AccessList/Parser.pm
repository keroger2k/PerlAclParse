package AccessList::Parser;

use strict;
use warnings;
use Carp;
use Scalar::Util 'blessed';
use Parse::RecDescent;
use IPAddressv4::IPHelp;

our $VERSION = '0.05';

my $iphelper = IPAddressv4::IPHelp->new;

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
	my $item = visit($tree);
	return $item;
}

#
# Finished tests
#

sub visit {
	my ($node) = @_;

	my $Rule_To_Key_Map = {
		"acl_action"              => 1,
		"acl_protocol"            => 1,
		"acl_src_ip"              => 1,
		"acl_src_port"            => 1,
		"acl_dst_ip"              => 1,
		"acl_dst_port"            => 1,
		"acl_remark"              => 1
	};

	my $parent_key;
	my $result;

	# set s of explored vertices
	my %seen;

	#stack is all neighbors of s
	my @stack;
	push @stack, [ $node, $parent_key ];

	my $key;

	while (@stack) {

		my $rec = pop @stack;

		$node       = $rec->[0];
		$parent_key = $rec->[1];    #undef for root

		next if ( $seen{$node}++ );

		my $rule_id = ref($node);

		if ( exists( $Rule_To_Key_Map->{$rule_id} ) ) {
			$parent_key = $rule_id;
		}

		foreach my $key ( keys %$node ) {
			next if ( $key eq "EOL" );
			my $next = $node->{$key};
			if ( blessed($next) ) {
				if ( exists( $next->{__VALUE__} ) ) {
			   		#print ref($node), " ", ref($next), " ", $next->{__VALUE__},"\n";
					my $rule  = ref($node);
					my $token = $next->{__VALUE__};
					$result->{$parent_key} = $token;
					#print $rule, " ", $result->{$rule}, "\n";
				}
				push @stack, [ $next, $parent_key ];
				#push @stack, $next;
			}
		}
	}
	return $result;
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
	| address CONNECTION_TYPE
	| address LAYER3_OPTIONS
	| IPRANGE

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
	  acl_logging LAYER3_OPTIONS
	|	acl_logging
	|	EOL
	|	<error>

acl_logging :
		 	"log-input"
	|		"log"
	
#
# IP address types
#
# "object" should be fine here because "object" can not  
# be used to specify ports 

address :
		"host" IPADDRESS
	|	"host" NAME
	|	IPNETWORK
	| WILDCARD_NETWORK
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
		/(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))/

INVERSE_MASK :
		/(0+|1|3|7|15|31|63|127|255)((\.)(255|127|63|31|15|7|3|1|0)){3}/

WILDCARD_NETWORK :
		/((\d{1,3})((\.)(\d{1,3})){3}) (0+|1|3|7|15|31|63|127|255)((\.)(255|127|63|31|15|7|3|1|0)){3}/

IPNETWORK :
		/((\d{1,3})((\.)(\d{1,3})){3}) (((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3}))/

IPRANGE :
		/((\d{1,3})((\.)(\d{1,3})){3}) ((\d{1,3})((\.)(\d{1,3})){3})/

PROTOCOL :
		/\d+/ | "ahp" | "eigrp" | "esp" | "gre" | "icmp" | "icmp6" | "igmp" 
	| "igrp" | "ip" | "ipinip" | "ipsec" | "nos" | "ospf" | "pcp" 
	| "pim" | "pptp" | "snp" | "tcp" | "udp" | "41" 

GROUP_PROTOCOL :
		"tcp-udp" | "tcp" | "udp"

ICMP_TYPE : 
		/\d+/ | "alternate-address" | "conversion-error" | "echo-reply" | "echo"
	| "information-reply" | "information-request" | "mask-reply" | "mask-request"
	| "mobile-redirect" | "parameter-problem" | "redirect" | "router-advertisement"
	| "router-solicitation" | "source-quench" | "time-exceeded" | "timestamp-reply"
	| "timestamp-request" | "traceroute" | "unreachable"

CONNECTION_TYPE:
		"established"

LAYER3_OPTIONS:
		"fragments" | "packet-too-big"

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