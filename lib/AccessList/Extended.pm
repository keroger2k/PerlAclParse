package AccessList::Extended;
use strict;
use warnings;
use AccessList::Generic;
use AccessList::Parser;

use base qw(AccessList::Generic);

###########################################################################################
# Description: Given an array of acl rules checks for overlaps
#
# Parameters:
#   array -> array of hashes that contain acl rules
#      hash structure:
#          'acl_action'    => '[permit], [deny]'
#          'acl_protocol'  => '[ip], [tcp], ...'
#          'acl_src_ip'    => '[<ip-address> <wildcard-mask>], [any], [host]'
#          'acl_dst_ip'    => '[<ip-address> <wildcard-mask>], [any], [host]'
#       #optional keys:
#          'acl_src_port'    => '[port name]'
#          'acl_dst_port'    => '[port name]'
#
# Returns: 
#   hash -> key -> network that has overlaps
#        -> value -> array of networks that are overlapped
#
###########################################################################################
sub check_rules_overlap {
  	my ($self, @addresses) = @_;
  	my $overlaps = {};

  	foreach my $line (@addresses) {
    	my @empty = ();
    
    	my $found_self = 0;

    	foreach my $inside_line (@addresses){

			if ( $line->{'acl_protocol'} eq $inside_line->{'acl_protocol'} &&
     			$line->{'acl_action'} eq $inside_line->{'acl_action'}) {
     			#since this looping same data twice, need to count out own entry
     	   		if(!$found_self && $line->{'acl_src_ip'} eq $inside_line->{'acl_src_ip'} && 
     	   			$line->{'acl_dst_ip'} eq $inside_line->{'acl_dst_ip'}) {
	     	       $found_self = 1;
	     	       next;
	     	   	}

	     	   	if($line->{'acl_src_ip'} eq $inside_line->{'acl_src_ip'}) {

	     	   		#check for destination overlap
	     	   		print "checking for destination overlaps\n";

	     	   	}

	     	   	if($line->{'acl_dst_ip'} eq $inside_line->{'acl_dst_ip'}) {

	     	   		#check for source overlap
	     	   		print "checking for source overlaps\n";

	     	   	}
     		}
  		}
  		
	}
	return $overlaps;
}


1;