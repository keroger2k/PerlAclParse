use strict;
use warnings;
use Test::More tests => 14;
use AccessList::Parser;

my $parser = AccessList::Parser->new();

ok( defined($parser), "constructor" );

my $string;
my $tree;
my $actual;
my $expected;

sub  get_rules {
  my @file_array = ();
  my $path = 'tmp/rules.txt';
  open (LIST, $path) || die "$path could not be opened: $!\nPlease check the file.\n";
  while(my $line = <LIST>){
    $line =~ s/\r\n$//g; #strip CRLF
    push @file_array, $line;
  }
  close(LIST);
  return @file_array;
}

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

#
# Access list 9
#

$string = q{deny   41 any any log};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'deny',
	'acl_protocol'  => '41',
	'acl_src_ip'    => 'any',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 9');

#
# Access list 10
#

$string = q{permit tcp any any established};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'tcp',
	'acl_src_ip'    => 'any',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 10');

#
# Access list 11
#

$string = q{permit ahp host 214.4.253.1 138.162.5.0 0.0.0.31};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'ahp',
	'acl_src_ip'    => '214.4.253.1',
	'acl_dst_ip'    => '138.162.5.0 0.0.0.31'
};

is_deeply($actual, $expected , 'Access list 11');

#
# Access list 12
#

$string = q{deny   icmp any any log fragments};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'deny',
	'acl_protocol'  => 'icmp',
	'acl_src_ip'    => 'any',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 12');

#
# Access list 13
#

$string = q{permit icmp any any packet-too-big};
$actual = $parser->parse($string);
$expected = {
	'acl_action'    => 'permit',
	'acl_protocol'  => 'icmp',
	'acl_src_ip'    => 'any',
	'acl_dst_ip'    => 'any'
};

is_deeply($actual, $expected , 'Access list 13');

#
# Parse Entire List
#

# my @empty = ();
# my @tmp = get_rules();
# foreach my $line (@tmp) {
#  	push @empty, $parser->parse($line);
# }

# is(scalar @empty, 7861, 'should be able to read entire acl and parse each rule');




