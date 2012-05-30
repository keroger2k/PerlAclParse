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
	my ($self, $section, @new_rules) = @_;
	my @new_acl = ();
	my $found = 0;

	if(scalar @new_rules == 0) { return; }

	foreach my $item (@{$self->{rules}}) {
		if( $item =~ /^ remark section (\d+)/i){
			if($section == $1){
				$found = 1;
				#if we don't send remark then this needs to be there.
				#push @new_acl, $item;
				foreach my $rule (@new_rules) {
					push @new_acl, $rule;
				}
			} elsif ($found){
				$found = 0;
			}
		} 
		if(!$found){
			push @new_acl, $item;
		}
	}
	@{$self->{rules}} = @new_acl;
}

###########################################################################################
# Description: Given a list of rules parses the rules and creates an array
# 	of hashes.
#
# Parameters: 
# 	@acl -> array -> list of rules
#
# Returns: 
# 	array -> array of hashes created by AccessList::Parser
#
###########################################################################################
sub read_acl {
	my ($self, @acl) = @_;
	my $parser = AccessList::Parser->new();
	my @result = ();

	foreach my $line (@acl) {
		my $parsed_line = $parser->parse($line);
		push @result, $parsed_line;
	}
	return @result;	
}

###########################################################################################
# Description: Check the entire ACL for overlap in all sections.
#
# Parameters: 
# 	uses rules hash provided with constructor
#
# Returns: 
# 	array -> array of hashes created by AccessList::Parser
#
###########################################################################################
sub check_all_sections_for_overlap {
	my ($self) = @_;
	my $parser = AccessList::Parser->new();
	my @result = ();
	my @tmp = @{$self->{rules}};
	shift(@tmp);
	foreach my $line (@tmp) {
		my $parsed_line = $parser->parse($line);
		push @result, $parsed_line;
	}
	return $self->check_rules_overlap(@result);	
}

1;