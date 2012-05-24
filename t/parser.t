use strict;
use warnings;
use Test::More tests => 9;
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
$actual = $parser->parse($string);
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
$actual = $parser->parse($string);
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
$actual = $parser->parse($string);
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
$actual = $parser->parse($string);
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
$actual = $parser->parse($string);
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
$actual = $parser->parse($string);
$expected = {
	'acl_remark'    => 'deny Navy internal spoofing'
};

is_deeply($actual, $expected , 'Access list 6');

#
# Access list 7
#

$string = q{permit tcp host 1.2.3.4 eq bgp host 5.6.7.8};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'tcp',
	'acl_src_ip'    => '1.2.3.4',
	'acl_dst_ip'    => '5.6.7.8',
	'acl_src_port' 	=> 'bgp'
};

is_deeply($actual, $expected , 'Access list 7');

#
# Access list 8
#

$string = q{deny   ip 24.80.0.0 0.7.255.255 any log-input};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'deny',
	'acl_protocol'  => 'ip',
	'acl_src_ip'    => '24.80.0.0 0.7.255.255',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 8');



