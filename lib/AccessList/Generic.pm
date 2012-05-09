package AccessList::Generic;
use strict;
use warnings;

sub new {
	my $class = shift;
	my $self = {
		rules => [],
		@_
	};
	bless $self, $class;
	return $self;
}

sub get_line_count {
	my $self = shift;
	return scalar @{$self->{rules}};
}

1;