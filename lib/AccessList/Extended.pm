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
    my $src_mask;
    my $dst_mask;
    my $line_src_network;
    my $line_src_broadcast;

    if($line->{'acl_src_ip'} eq 'any') {
      $line_src_network = $self->get_int_ip_network_from_string('0.0.0.0', '0.0.0.0');  
      $line_src_broadcast = $self->get_broadcast_int_address_from_string('0.0.0.0', '0.0.0.0');
    } elsif (scalar(split / /, $line->{'acl_src_ip'}) == 1) {
      $line_src_network = $self->get_int_ip_network_from_string($line->{'acl_src_ip'}, '255.255.255.255');  
      $line_src_broadcast = $self->get_broadcast_int_address_from_string($line->{'acl_src_ip'}, '255.255.255.255');
    } else {
      my ($src_address, $src_inverse) = split / /, $line->{'acl_src_ip'};
      $line_src_network = $self->get_int_ip_network_from_string($src_address, flip_the_bits($src_inverse));  
      $line_src_broadcast = $self->get_broadcast_int_address_from_string($src_address, flip_the_bits($src_inverse));
    }

    #my $found_self = 0;

    # foreach my $inside_line (@addresses){
      
    #   if(!$found_self && ($line eq $inside_line)) {
    #     $found_self = 1;
    #     next;
    #   }

    #   my @inside_tmp = split / /, $inside_line;
    
    #   my $inside_line_network = $self->get_int_ip_network_from_string($inside_tmp[0], $inside_tmp[1]);
    #   my $inside_line_broadcast = $self->get_broadcast_int_address_from_string($inside_tmp[0], $inside_tmp[1]);

    #   if($line_network <= $inside_line_network && $line_broadcast >= $inside_line_broadcast) {
    #     push @empty, $inside_line;
    #   }
    # }
    
    # if(scalar @empty > 0){
    #   $overlaps->{$line} = \@empty;
    # }

  }
  return $overlaps;
}


1;