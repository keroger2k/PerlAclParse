package AccessList::Extended;
use strict;
use warnings;
use IPAddressv4::IPHelp;
use AccessList::Generic;
use AccessList::Parser;

use base qw(AccessList::Generic);

my $iphelper = IPAddressv4::IPHelp->new;

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

      if(defined($line->{'acl_remark'}))  {
         next;
      }

  	foreach my $inside_line (@addresses){

      #no need to parse remarks
      if(defined($inside_line->{'acl_remark'}))  {
         next;
      }

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

   	   		my @tmp = ();
   	   		my @inside_tmp = ();
   	   		my $inside_host_entry = 0;

   	   		if($line->{'acl_dst_ip'} eq 'any') {
   	   			@tmp = ('0.0.0.0', '255.255.255.255');
   	   		} else {
   	   			@tmp = split / /, $line->{'acl_dst_ip'};
   	   			#check if this is just a host address
   	   			if(scalar @tmp != 2) {
   	   				$tmp[1] = '0.0.0.0';
   	   				$inside_host_entry = 1;
   	   			}
					}

   	   		if($inside_line->{'acl_dst_ip'} eq 'any') {
   	   			@inside_tmp = ('0.0.0.0', '255.255.255.255');
   	   		} else {
   	   		  @inside_tmp = split / /, $inside_line->{'acl_dst_ip'};
   	   		  #check if this is just a host address
   	   			if(scalar @inside_tmp != 2) {
   	   				$inside_tmp[1] = '0.0.0.0';
   	   				$inside_host_entry = 1;
   	   			}
   	   		}

   	   		$tmp[1] = $iphelper->inverse_to_subnetmask($tmp[1]);
   	   		$inside_tmp[1] = $iphelper->inverse_to_subnetmask($inside_tmp[1]);
   	   		
   	   		my $line_network = $iphelper->get_int_ip_network_from_string($tmp[0], $tmp[1]);
					my $line_broadcast = $iphelper->get_broadcast_int_address_from_string($tmp[0], $tmp[1]);
               my $inside_line_network = $iphelper->get_int_ip_network_from_string($inside_tmp[0], $inside_tmp[1]);
               my $inside_line_broadcast = $iphelper->get_broadcast_int_address_from_string($inside_tmp[0], $inside_tmp[1]);

   		      if($line_network <= $inside_line_network && $line_broadcast >= $inside_line_broadcast) {
   		      	my $val = 
   		      		$inside_line->{'acl_action'} . " " . 
   		      		$inside_line->{'acl_protocol'} . " " . 
   						$inside_line->{'acl_src_ip'} . " " . 
   						((defined($inside_line->{'acl_src_port'})) ? $inside_line->{'acl_src_port'} . " " : "") . 
   						(($inside_host_entry) ? "host " : "") . 
   						$inside_line->{'acl_dst_ip'} . 
   						((defined($inside_line->{'acl_dst_port'})) ? " " . $inside_line->{'acl_dst_port'} : "");
   					push @empty, $val;
   		      }
   	   	}

   	   	if($line->{'acl_dst_ip'} eq $inside_line->{'acl_dst_ip'}) {

   	   		#check for source overlap
   	   		my @tmp = ();
   	   		my @inside_tmp = ();
   	   		my $inside_host_entry = 0;

   	   		if($line->{'acl_src_ip'} eq 'any') {
   	   			@tmp = ('0.0.0.0', '0.0.0.0');
   	   		} else {
   	   			@tmp = split / /, $line->{'acl_src_ip'};
   	   			#check if this is just a host address
   	   			if(scalar @tmp != 2) {
   	   				$tmp[1] = '0.0.0.0';
   	   				$inside_host_entry = 1;
   	   			}
					}

   	   		if($inside_line->{'acl_src_ip'} eq 'any') {
   	   			@inside_tmp = ('0.0.0.0', '0.0.0.0');
   	   		} else {
   	   		  @inside_tmp = split / /, $inside_line->{'acl_src_ip'};
   	   		  #check if this is just a host address
   	   			if(scalar @inside_tmp != 2) {
   	   				$inside_tmp[1] = '0.0.0.0';
   	   				$inside_host_entry = 1;
   	   			}
   	   		}

   	   		$tmp[1] = $iphelper->inverse_to_subnetmask($tmp[1]);
   	   		$inside_tmp[1] = $iphelper->inverse_to_subnetmask($inside_tmp[1]);


   	   		my $line_network = $iphelper->get_int_ip_network_from_string($tmp[0], $tmp[1]);
					my $line_broadcast = $iphelper->get_broadcast_int_address_from_string($tmp[0], $tmp[1]);
   		      my $inside_line_network = $iphelper->get_int_ip_network_from_string($inside_tmp[0], $inside_tmp[1]);
   		      my $inside_line_broadcast = $iphelper->get_broadcast_int_address_from_string($inside_tmp[0], $inside_tmp[1]);

   		      if($line_network <= $inside_line_network && $line_broadcast >= $inside_line_broadcast) {
   					my $val = $inside_line->{'acl_action'} . " " . 
   						$inside_line->{'acl_protocol'} . " " . 
   						(($inside_host_entry) ? "host " : "") .
   						$inside_line->{'acl_src_ip'} . " " . 
   						((defined($inside_line->{'acl_src_port'})) ? $inside_line->{'acl_src_port'} . " " : "") . 
   						$inside_line->{'acl_dst_ip'} .
   			         ((defined($inside_line->{'acl_dst_port'})) ? $inside_line->{'acl_dst_port'} . " " : "");
   					push @empty, $val;
   		      }
   	   	}
   		}
		}

		#went through the outside loop, now look if there were any overlaps
		if(scalar @empty > 0){
			my $key = $line->{'acl_action'} . " " . $line->{'acl_protocol'} . " " . $line->{'acl_src_ip'} . " " . $line->{'acl_dst_ip'};
	  	$overlaps->{$key} = \@empty;
		}

	}
	return $overlaps;
}


1;