package AccessList::Extended;
use strict;
use warnings;
use IPAddressv4::IPHelp;
use AccessList::Generic;
use AccessList::Parser;

use base qw(AccessList::Generic);

my $iphelper = IPAddressv4::IPHelp->new;
my $parser  = AccessList::Parser->new;

###########################################################################################
# Description: Translate IOS terminology into actual ip addresses
#
# Parameters:
#   $address -> string
#
# Returns: 
#   hash  -> contains, network, mask and if the entry was a host entry
###########################################################################################
sub normalize_ip {
  my ($self, $address) = @_;
  my $tmp = {};
  $tmp->{'is_host_entry'} = 0;

  if($address eq 'any') {
    $tmp->{'network'} = '0.0.0.0';
    $tmp->{'mask'} = '255.255.255.255';
  } else {
    my @tmp_arr = split / /, $address;
    $tmp->{'network'} = $tmp_arr[0];
    #check if this is just a host address
    if(scalar @tmp_arr != 2) {
      $tmp->{'mask'} = '0.0.0.0';
      $tmp->{'is_host_entry'} = 1;
    } else {
      $tmp->{'mask'} = $tmp_arr[1];
    }
  }
  return $tmp;
}

###########################################################################################
# Description: Speed seems to be an issue with this so I'm pre-converting all the 
#              IP addresses and such into Unsigned Integers to make logic and code
#              easier to read. 
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
#          'is_host_entry'   => 'bool'
#
# Returns: 
#   array -> array of hashes.  Same as input with extra params.
#         'acl_dst_network', 'acl_dst_broadcast', 'acl_src_network', 'acl_src_broadcast'
###########################################################################################
sub normalize_parsed_array {
   my ($self, @addresses) = @_;
   my $current_section = 1;
   my $current_line = 1;

   foreach my $line (@addresses) {
      $line->{'line'} = $current_line++;
      if(defined($line->{'acl_remark'}))  {
        #remark Section # -- Description
        if($line->{'acl_remark'} =~ /^section (\d+)/i){
          $current_section = $1;
        }
        next;
      }

      $line->{'section'} = $current_section;

      my $tmp_dst = $self->normalize_ip($line->{'acl_dst_ip'});
      my $tmp_src = $self->normalize_ip($line->{'acl_src_ip'});

      $line->{'is_host_entry'} = $tmp_dst->{'is_host_entry'} || $tmp_src->{'is_host_entry'}; 
      
      $tmp_dst->{'mask'} = $iphelper->inverse_to_subnetmask($tmp_dst->{'mask'});
      $tmp_src->{'mask'} = $iphelper->inverse_to_subnetmask($tmp_src->{'mask'});


      $line->{'acl_dst_network'} = $iphelper->get_int_ip_network_from_string($tmp_dst->{'network'}, $tmp_dst->{'mask'});
      $line->{'acl_dst_broadcast'} = $iphelper->get_broadcast_int_address_from_string($tmp_dst->{'network'}, $tmp_dst->{'mask'});
      $line->{'acl_src_network'} = $iphelper->get_int_ip_network_from_string($tmp_src->{'network'}, $tmp_src->{'mask'});
      $line->{'acl_src_broadcast'} = $iphelper->get_broadcast_int_address_from_string($tmp_src->{'network'}, $tmp_src->{'mask'});
   }
   return @addresses;
}

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
#          'is_host_entry'   => 'bool'
#
# Returns: 
#   hash -> key -> network that has overlaps
#        -> value -> array of networks that are overlapped
#
###########################################################################################
sub check_rules_overlap {
	my ($self, @addresses) = @_;
	my $overlaps = {};

   my @normalized_addresses = $self->normalize_parsed_array(@addresses);

   foreach my $line (@normalized_addresses) {
      my @empty = ();
      my $found_self = 0;

      #no need to parse remarks
      if(defined($line->{'acl_remark'}))  {
         next;
      }

      foreach my $inside_line (@normalized_addresses){

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
             if($line->{'acl_dst_network'} <= $inside_line->{'acl_dst_network'} && 
               $line->{'acl_dst_broadcast'} >= $inside_line->{'acl_dst_broadcast'}) {
               my $val = 
               $inside_line->{'acl_action'} . " " . 
               $inside_line->{'acl_protocol'} . " " . 
               $inside_line->{'acl_src_ip'} . " " . 
               ((defined($inside_line->{'acl_src_port'})) ? $inside_line->{'acl_src_port'} . " " : "") . 
               (($inside_line->{'is_host_entry'}) ? "host " : "") . 
               $inside_line->{'acl_dst_ip'} . 
               ((defined($inside_line->{'acl_dst_port'})) ? " " . $inside_line->{'acl_dst_port'} : "")
               . " (S:" . $line->{'section'} . ")/(L:" . $inside_line->{'line'} . ")";
                push @empty, $val;
            }
         }

         if($line->{'acl_dst_ip'} eq $inside_line->{'acl_dst_ip'}) {
   	   		#check for source overlap
             if($line->{'acl_src_network'} <= $inside_line->{'acl_src_network'} && 
               $line->{'acl_src_broadcast'} >= $inside_line->{'acl_src_broadcast'}) {
                my $val = $inside_line->{'acl_action'} . " " . 
                $inside_line->{'acl_protocol'} . " " . 
                (($inside_line->{'is_host_entry'}) ? "host " : "") .
                $inside_line->{'acl_src_ip'} . " " . 
                ((defined($inside_line->{'acl_src_port'})) ? $inside_line->{'acl_src_port'} . " " : "") . 
                $inside_line->{'acl_dst_ip'} .
                ((defined($inside_line->{'acl_dst_port'})) ? $inside_line->{'acl_dst_port'} . " " : "")
               . " (S:" . $line->{'section'} . ")/(L:" . $inside_line->{'line'} . ")";
               push @empty, $val;
             }
          }
       }
    }

		#went through the outside loop, now look if there were any overlaps
		if(scalar @empty > 0){
			my $key = $line->{'acl_action'} . " " . $line->{'acl_protocol'} . " " . $line->{'acl_src_ip'} . " " . $line->{'acl_dst_ip'} . " (S:" . $line->{'section'} . ")/(L:" . $line->{'line'} . ")" ;
        $overlaps->{$key} = \@empty;
     }

  }
  return $overlaps;
}


1;