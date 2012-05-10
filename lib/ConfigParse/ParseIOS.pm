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
	my ($self) = @_;
	my %acl_hash = ();
	for my $i (0 .. $#{$self->{file}}) { 
		if(${$self->{file}}[$i] =~ /^ip access-list extended (\S+)/){
			my @t = ();
			push @t, ${$self->{file}}[$i++];
			while(${$self->{file}}[$i] =~ /^ /) {
				push @t, ${$self->{file}}[$i++];
			}
			@{$acl_hash{$1}} = @t;
			$i--;
		}
	}
	return %acl_hash;
}

sub parse_acls1 {
	my ($self) = @_;
	my %acl_hash = ();
	my $found = 0;
	my $flag = "";
	my @t = ();
	foreach my $item (@{$self->{file}}) {
		if( $item =~ /^ip access-list extended (\S+)/i){
			
			if($flag ne $1){
				$flag = $1;
				$found = 1;
				@t = ();
				$acl_hash{$flag} = \@t;
			} 
		} 
		if($found){
			push @t, $item;
		}
	}
	return %acl_hash;
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