package ConfigParse::ParseIOS;

use strict;
use warnings;

sub new {
  my ($class) = @_;
  my $self = bless {}, $class;
  return $self;
}

###########################################################################################
# Description: Simply open a file or die.
#
# Parameters:
# 	$path -> string -> path to the file on disk
#
# Returns: 
#	@file_array -> array of strings -> contents of the file put into 
# 		array.
#
###########################################################################################
sub open_file {
	my ($self, $path) = @_;
	my @file_array = ();
	open (LIST, $path) || die "$path could not be opened: $!\nPlease check the file.\n";
	while(my $line = <LIST>){
		$line =~ s/\r\n$//g; #strip CRLF
		push @file_array, $line;
	}
	close(LIST);
	return @file_array;
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
	my ($self, @file_array) = @_;
	my @acl_list = ();
	my %acl_hash = ();
	for my $i (0 .. $#file_array) { 
		if($file_array[$i] =~ /^ip access-list extended (\S+)/){
			my @t = ();
			push @t, $file_array[$i++];
			while($file_array[$i] =~ /^ /) {
				push @t, $file_array[$i++];
			}
			@{$acl_hash{$1}} = @t;
			$i--;
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