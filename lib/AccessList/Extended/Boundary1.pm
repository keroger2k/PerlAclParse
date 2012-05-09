package AccessList::Extended::Boundary1;
use strict;
use warnings;

use base qw(AccessList::Extended);

###########################################################################################
# Description: Extract a specific section of an access list.
#
# Parameters: 
# 	$section -> int -> section number to be extracted
#
# Returns: 
# 	array -> entire section of of acl from remark Section to next 
#		remark Section
#
###########################################################################################
sub get_acl_section {
	my ($self, $section) = @_;
	my @section_content = ();
	my $found = 0;

	foreach my $item (@{$self->{rules}}) {
		if( $item =~ /^ remark section (\d+)/i){
			if($section == $1){
				$found = 1;
			} elsif ($found) {
				return @section_content;
			}
		} 
		if($found){
			push @section_content, $item;
		}
	}
	return @section_content;
}

###########################################################################################
# Description: Replace a section in an existing access list with the
# 	new rules supplied
#
# Parameters: 
# 	$section -> int -> section number to be extracted
# 	@new_rules -> array -> list of new rules
#
# Returns: 
# 	array -> entire acl with updated section incoproated
#
###########################################################################################
sub replace_section {

}

1;