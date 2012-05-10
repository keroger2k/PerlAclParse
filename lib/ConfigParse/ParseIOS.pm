package ConfigParse::ParseIOS;

use strict;
use warnings;

sub new {
  my ($class) = shift;
  my $self = {
  	file => [],
  	@_
  };
  bless $self, $class;
  return $self;
}

###########################################################################################
# Description: Take a configuration file and parse out all the ACLs
# 	in the file and store them into a hash.
#
# Parameters: 
# 	@file_array -> array -> array of the contents of configurations.
#
# Returns: 
# 	%acl_hash -> hash of arrays -> all the acls stored in arrays inside
# 	a hash.
#
###########################################################################################
sub parse_acls {
  my $self = shift;
  my %acl_hash = ();
  my @acl_entries = ();
  my $in_acl = 0;
  my $acl_name = "";

  foreach my $i (@{$self->{file}}) {
    if ($i =~ /^ip access-list extended (\S+)/) {
      if ($in_acl) {
        @{$acl_hash{$acl_name}} = @acl_entries;
        @acl_entries = ();
      }
      $in_acl = 1;
      $acl_name = $1;
      push @acl_entries, $i;
    } elsif ($i =~ /^!/) {
      if ($in_acl) {
        @{$acl_hash{$acl_name}} = @acl_entries;
        $in_acl = 0;  
      }
    } elsif ($i =~ /^end/) {
      return %acl_hash;
    } elsif ($in_acl) {
      push @acl_entries, $i;
    }
  }
}

###########################################################################################
# Description: Get the versions of the ACL name sent in descending order 
#
# Parameters:
#  	$ref 	-> reference to hash -> reference to has of ACLs
# 	$name 	-> name of acls to get version
#
# Returns: 
# 	@arr 	-> integer array -> array of version ordered descending.
#
###########################################################################################
sub get_version {
  my ($self, $ref, $name) = @_;
  my @arr = ();

  foreach my $key (sort { $b cmp $a} keys %{$ref}) {
    if($key =~ /$name(\d+)/){
    	push @arr, $1;
    }
  }
  return @arr;
}

1;