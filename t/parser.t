use strict;
use warnings;
use Scalar::Util 'blessed';
use Test::More tests => 8;
use AccessList::Parser;

my $parser = AccessList::Parser->new();

ok( defined($parser), "constructor" );

my $string;
my $tree;
my $actual;
my $expected;

#
# Access list 1
#

$string = q{permit ip any 1.2.0.0 0.0.255.255};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'ip',
	'acl_src_ip'    => 'any',
	'acl_dst_ip'    => '1.2.0.0 0.0.255.255'
};

is_deeply($actual, $expected , 'Access list 1');


#
# Access list 2
#

$string = q{permit ip host 1.2.3.4 1.2.3.4 0.0.0.31};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'ip',
	'acl_src_ip'    => '1.2.3.4',
	'acl_dst_ip'    => '1.2.3.4 0.0.0.31'
};

is_deeply($actual, $expected , 'Access list 2');

#
# Access list 3
#

$string = q{deny   ip 1.2.3.4 0.0.0.255 any log-input};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'deny',
	'acl_protocol'  => 'ip',
	'acl_src_ip'    => '1.2.3.4 0.0.0.255',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 3');

#
# Access list 4
#

$string = q{permit tcp host 1.2.3.4 host 5.6.7.8 eq 416};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'tcp',
	'acl_src_ip'    => '1.2.3.4',
	'acl_dst_ip'    => '5.6.7.8',
	'acl_dst_port' 	=> '416'
};

is_deeply($actual, $expected , 'Access list 4');

#
# Access list 5
#

$string = q{permit tcp host 1.2.3.4 host 5.6.7.8 eq bgp};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'tcp',
	'acl_src_ip'    => '1.2.3.4',
	'acl_dst_ip'    => '5.6.7.8',
	'acl_dst_port' 	=> 'bgp'
};

is_deeply($actual, $expected , 'Access list 5');

#
# Access list 6
#

$string = q{remark deny Navy internal spoofing};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_remark'    => 'deny Navy internal spoofing'
};

is_deeply($actual, $expected , 'Access list 6');

#
# Access list 7
#

$string = q{permit tcp host 1.2.3.4 eq bgp host 5.6.7.8};
$tree = $parser->parse($string);
$actual = visit($tree);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'tcp',
	'acl_src_ip'    => '1.2.3.4',
	'acl_dst_ip'    => '5.6.7.8',
	'acl_src_port' 	=> 'bgp'
};

is_deeply($actual, $expected , 'Access list 7');


#
# Finished tests
#

sub visit {
	my ($node) = @_;

	my $Rule_To_Key_Map = {
		"acl_action"              => 1,
		"acl_protocol"            => 1,
		"acl_src_ip"              => 1,
		"acl_src_port"            => 1,
		"acl_dst_ip"              => 1,
		"acl_dst_port"            => 1,
		"acl_remark"              => 1
	};

	my $parent_key;
	my $result;

	# set s of explored vertices
	my %seen;

	#stack is all neighbors of s
	my @stack;
	push @stack, [ $node, $parent_key ];

	my $key;

	while (@stack) {

		my $rec = pop @stack;

		$node       = $rec->[0];
		$parent_key = $rec->[1];    #undef for root

		next if ( $seen{$node}++ );

		my $rule_id = ref($node);

		if ( exists( $Rule_To_Key_Map->{$rule_id} ) ) {
			$parent_key = $rule_id;
		}

		foreach my $key ( keys %$node ) {
			next if ( $key eq "EOL" );
			my $next = $node->{$key};
			if ( blessed($next) ) {
				if ( exists( $next->{__VALUE__} ) ) {
			   		#print ref($node), " ", ref($next), " ", $next->{__VALUE__},"\n";
					my $rule  = ref($node);
					my $token = $next->{__VALUE__};
					$result->{$parent_key} = $token;
					#print $rule, " ", $result->{$rule}, "\n";
				}
				push @stack, [ $next, $parent_key ];
				#push @stack, $next;
			}
		}
	}
	return $result;
}