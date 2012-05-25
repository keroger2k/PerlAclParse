package IPAddressv4::IPHelp;

use strict;
use warnings;

sub new {
  my ($class) = @_;
  my $self = bless {}, $class;
  return $self;
}

###########################################################################################
# Description: Take a string ip address and converts it to an integer
#
# Parameters:
#  - token -> array -> tokenized version of ip address split into octets
#  - "1.2.3.4" would result into -> (1,2,3,4)
# Returns: 
# - integer version of ip address
# - "192.168.10.10" returns "3232238090"
#
###########################################################################################
sub convert_ip_to_integer {
  my $self = shift(@_);
  my @token = split '\.', shift(@_);
  my ($intip, $shift) = (0, 24);
  foreach my $temp (@token) {
    $intip |= ($temp+0) << $shift;
    $shift -= 8;
  }
  return $intip;
}

###########################################################################################
# Description: Take an integer form of an ip address and convert it back to a string.
#
# Parameters:
#   $intip -> integer -> integer of an ip address
#
# Returns: 
#   string -> string representation of dotted decimal address
#
###########################################################################################
sub convert_integer_to_ip {
  my ($self, $intip) = @_;
  return ($intip >> 24) . "." . (($intip & 0x00ff0000) >> 16) . "." . (($intip & 0x0000ff00) >> 8) . "." . ($intip & 0x000000ff);
}

###########################################################################################
# Description: Given an ip address and netmask, determines the network address
#
# Parameters:
#   @ipv4 -> string -> dotted decimal version of ip address; gets split into an array 
#     on shift
#   @m    -> string -> dotted decimal version of netmask; gets split into an array
#     on shift
#   
# Returns: 
#   string -> dotted decimal version of network addreess for ip address
#
###########################################################################################
sub get_ip_network {
  my $self = shift(@_);
  my @IPv4 = split '\.', shift(@_);
  my @M = split '\.', shift(@_);
  my $Mask0 = $M[0] - 0; my $Mask1 = $M[1] - 0; my $Mask2 = $M[2] - 0; my $Mask3 = $M[3] - 0;
  return sprintf "%d\.%d\.%d\.%d", ($IPv4[0] & $Mask0), ($IPv4[1] & $Mask1), ($IPv4[2] & $Mask2), ($IPv4[3] & $Mask3);
}

###########################################################################################
# Description: Given an ip address and netmask, determines the network address
#
# Parameters:
#   @ipv4 -> string -> dotted decimal version of ip address; gets split into an array 
#     on shift
#   @m    -> string -> dotted decimal version of netmask; gets split into an array
#     on shift
#   
# Returns: 
#   string -> dotted decimal version of network addreess for ip address
#
###########################################################################################
sub get_int_ip_network_from_string {
  my $self = shift(@_);
  my @IPv4 = split '\.', shift(@_);
  my @M = split '\.', shift(@_);
  my $Mask0 = $M[0] - 0; my $Mask1 = $M[1] - 0; my $Mask2 = $M[2] - 0; my $Mask3 = $M[3] - 0;
  my $result = sprintf "%d\.%d\.%d\.%d", ($IPv4[0] & $Mask0), ($IPv4[1] & $Mask1), ($IPv4[2] & $Mask2), ($IPv4[3] & $Mask3);
  return $self->convert_ip_to_integer($result);
}

###########################################################################################
# Description: Given an ip address and netmask, determines the broadcast address.
#
# Parameters:
#   integer -> ip address
#   integer -> netmask 
#
# Returns: 
#   integer -> integer version of broadcast address.
#
###########################################################################################
sub get_broadcast_address {
  my $self = shift(@_);
  return (shift(@_) | (0xffffffff ^ shift(@_)));
}

###########################################################################################
# Description: Given an ip address and netmask, determines the broadcast address.
#
# Parameters:
#   string -> ip address
#   string -> netmask 
#
# Returns: 
#   integer -> integer version of broadcast address.
#
###########################################################################################
sub get_broadcast_int_address_from_string {
  my $self = shift(@_);
  my $net = $self->convert_ip_to_integer(shift(@_));
  my $mask = $self->convert_ip_to_integer(shift(@_));
  return ($net | (0xffffffff ^ $mask));
}

###########################################################################################
# Description: Given the number of bits in a netmask (e.g. 27, 28, etc...) converts
# into a string in dotted decimal notation.
#
# Parameters:
#   integer -> number of bits represented in the netmask
#
# Returns: 
#   string  -> dotted decimal version of netmask. 
#
###########################################################################################
sub convert_cidr_to_netmask {
  my ($self, $Bits) = @_;
  if ($Bits > 31) {
    return '255.255.255.255';
  }
  my ($octet, $Mask) = (4, '');
  while ($octet--) {
    if ($Bits < 8) {
      my $value = (0xFF00 >> $Bits) & 0xFF;
      $Mask = $Mask.".$value";
      $Bits = 0;
    } else {
      $Bits -= 8;
      $Mask = $Mask.'.255';
    }
  }
  substr $Mask, 0, 1, '';
  return $Mask;
}

###########################################################################################
# Description: Given a network address and mask determines if an ip address falls 
#     within the network range.
#
# Parameters:
#   string -> dotted decimal version of ip address to test if falls inside range
#   string -> dotted decimal network address
#   string -> dotted decimal netmask
#
# Returns: 
#   bool  -> true/false if it falls inside range
#
###########################################################################################
sub ip_inside_range {
  my $self = shift(@_);
  my ($IPv4, $Network, $Mask) = ($self->convert_ip_to_integer(shift(@_)), 
      $self->convert_ip_to_integer(shift(@_)), 
      $self->convert_ip_to_integer(shift(@_)));
  my $Broadcast = $self->get_broadcast_address($Network, $Mask);
  return (($IPv4 < $Network) || ($IPv4 > $Broadcast)) ? 0 : 1;
}

###########################################################################################
# Description: Given an array of dotted decimal ip addresses sorts based on integer
#   value of each octet
#
# Parameters:
#   array -> array of addresses in dotted decimal format
#
# Returns: 
#   array -> array of sorted addresses in dotted decimal format
#
###########################################################################################
sub sort_ip_addresses{
  my ($self, @addresses) = @_;
  my @sortedList = ();
  my @sortedAddresses = ();
  foreach my $address (@addresses) {
    push @sortedList, $self->convert_ip_to_integer($address);
  }

  my @articles = sort {$a <=> $b} @sortedList;

  foreach my $address (@articles){
    push @sortedAddresses, $self->convert_integer_to_ip($address);
  }

  return @sortedAddresses; 
}

###########################################################################################
# Description: Given a list of ip address will determine addresses that overlap
#
# Parameters:
#   array -> array of addresses in dotted decimal format to check for overlap
#
# Returns: 
#   hash -> key -> network that has overlaps
#        -> value -> array of networks that are overlapped
#
###########################################################################################
sub check_for_overlap {
  my ($self, @addresses) = @_;
  my $overlaps = {};

  foreach my $line (@addresses) {
    my @empty = ();
    my @tmp = split / /, $line;
    
    my $line_network = $self->get_int_ip_network_from_string($tmp[0], $tmp[1]);
    my $line_broadcast = $self->get_broadcast_int_address_from_string($tmp[0], $tmp[1]);

    my $found_self = 0;

    foreach my $inside_line (@addresses){
      
      if(!$found_self && ($line eq $inside_line)) {
        $found_self = 1;
        next;
      }

      my @inside_tmp = split / /, $inside_line;
    
      my $inside_line_network = $self->get_int_ip_network_from_string($inside_tmp[0], $inside_tmp[1]);
      my $inside_line_broadcast = $self->get_broadcast_int_address_from_string($inside_tmp[0], $inside_tmp[1]);

      if($line_network <= $inside_line_network && $line_broadcast >= $inside_line_broadcast) {
        push @empty, $inside_line;
      }
    }
    
    if(scalar @empty > 0){
      $overlaps->{$line} = \@empty;
    }

  }
  return $overlaps;
}

###########################################################################################
# Description: Converts an inverse mask into a subnet mask.
#
# Parameters:
#   string -> dotted decimal version of an inverse mask
#
# Returns: 
#   string -> dotted decimal version of a subnet mask
#
###########################################################################################
sub inverse_to_subnetmask {
  my $self = shift(@_);
  my @b = split '\.', shift(@_);
  return (sprintf "%d\.%d\.%d\.%d", (255-$b[0]), (255-$b[1]), (255-$b[2]), (255-$b[3]));
}

1;
