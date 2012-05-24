package AccessList::Extended;
use strict;
use warnings;
use AccessList::Generic;

use base qw(AccessList::Generic);

###########################################################################################
# Description: Given a array of rules from an acl return an array with just the source
#   	addresses defined in the acl.
#
# Parameters: 
# 	@acl_section -> array -> rules from an acl
#
# Returns: 
# 	array -> addresses defined in the source
#
# Remarks:
# 	This is an extended ACL with the following format:
#  		<permit/deny> <protocol> <source> <destination> <log option>
#
#	<permit/deny> 	- defines if the rule is permitting or denying access
#  	<protocol> 		- tcp, ospf, ip, etc..
# 	<source/wildcard>		- source network range, can be host (/32) or any (/0)
# 	<destination/wildcard> 	- destination network range, can also host (/32) or any (/0)
# 	<log options> 	- defines if you log or not
###########################################################################################
sub get_acl_source_values {
	my ($self, @acl) = @_;
	my @sources = ();

	foreach my $line (@acl) {

	}
	return @sources;
}

sub parse_rule {
	my ($self, $rule) = @_;

	my %rule_parsed = ();
	$rule_parsed{'acl_action'} = $1 if $rule =~ m/(permit|deny)/;
	$rule_parsed{'protocol'} = $1 if $rule =~ m/(tcp|ip)/;
	return %rule_parsed;
}

1;