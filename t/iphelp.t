use strict;
use warnings;
use Test::More tests => 13;

BEGIN { use_ok('IPAddressv4::IPHelp'); }

can_ok('IPAddressv4::IPHelp', 'new');

subtest 'testing convert_ip_to_integer' => sub {
  plan tests => 3;
  my $p = IPAddressv4::IPHelp->new;
  isa_ok($p, 'IPAddressv4::IPHelp');
  can_ok('IPAddressv4::IPHelp', 'convert_ip_to_integer');
  is($p->convert_ip_to_integer('192.168.10.10'), '3232238090', 'should convert a string ip address to an integer');
};

subtest 'testing convert_integer_to_ip' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'convert_integer_to_ip');
  is($p->convert_integer_to_ip('3232238090'), '192.168.10.10', 'should convert an integer to a string ip address');
};

subtest 'testing get_ip_network' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'get_ip_network');
  is($p->get_ip_network('10.1.1.32', '255.255.254.0'), '10.1.0.0', 'should return network address given and string ip address and string netask');
};

subtest 'testing get_int_ip_network_from_string' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'get_int_ip_network_from_string');
  is($p->get_int_ip_network_from_string('10.1.1.32', '255.255.254.0'), 167837696, 'should return network address given and string ip address and string netask');
};

subtest 'testing get_broadcast_address' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'get_broadcast_address');
  my $net = $p->convert_ip_to_integer('10.1.1.33');
  my $mask = $p->convert_ip_to_integer('255.255.254.0');
  is($p->get_broadcast_address($net,$mask), 167838207, 'should return broacast address as integer given an integer ip address and integer netmask');
};

subtest 'testing get_broadcast_int_address_from_string' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'get_broadcast_int_address_from_string');
  my $net = '10.1.1.33';
  my $mask = '255.255.254.0';
  is($p->get_broadcast_int_address_from_string($net,$mask), 167838207, 'should return broacast address as integer given an integer ip address and integer netmask');
};

subtest 'testing convert_cidr_to_netmask' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'convert_cidr_to_netmask');
  is($p->convert_cidr_to_netmask(23), '255.255.254.0', 'should convert a integer netmask in cidr notation to string netmask in long notation');
};

subtest 'testing ip_inside_range' => sub {
  plan tests => 3;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'ip_inside_range');
  is($p->ip_inside_range('10.1.1.23', '10.1.1.0', '255.255.255.0'), 1, 'given address inside range should return true');
  is($p->ip_inside_range('10.1.2.23', '10.1.1.0', '255.255.255.0'), 0, 'given address outside range should return false');
};

subtest 'testing sort_ip_addresses' => sub {
  plan tests => 2;
  my $p = IPAddressv4::IPHelp->new;
  can_ok('IPAddressv4::IPHelp', 'sort_ip_addresses');
  my @test = $p->sort_ip_addresses(('10.20.40.40', '10.20.30.30', '10.19.10.10', '9.9.9.9'));
  is_deeply(\@test, 
    ['9.9.9.9', '10.19.10.10', '10.20.30.30', '10.20.40.40'], 
    'given and unsort list of ip address it should return sorted numerically');
};

subtest 'testing check_for_overlap' => sub {
 plan tests => 2;
 my $p = IPAddressv4::IPHelp->new;
 can_ok('IPAddressv4::IPHelp', 'check_for_overlap');

 my @sent = ('10.0.0.0 255.255.255.224', '10.0.0.32 255.255.255.224', 
   '10.0.0.64 255.255.255.224', '10.0.0.96 255.255.255.224');
 my $result = $p->check_for_overlap(@sent);
 my $expected = {};

 is_deeply(\$result, \$expected, 
   'given a list of ip addresses with no overlap an empty array will be returned');
};

subtest 'testing check_for_overlap' => sub {
 plan tests => 2;
 my $p = IPAddressv4::IPHelp->new;
 can_ok('IPAddressv4::IPHelp', 'check_for_overlap');

 my @sent = ('10.0.0.0 255.255.255.0', '10.0.0.32 255.255.255.224', 
   '10.0.0.64 255.255.255.224', '10.0.1.96 255.255.255.224');

 my $result = $p->check_for_overlap(@sent);
 my %expected = ('10.0.0.0 255.255.255.0' => 
            ['10.0.0.32 255.255.255.224','10.0.0.64 255.255.255.224']);
 
 is_deeply(\%$result, \%expected, 
   'given a list of ip addresses with overlap an array will be returned with overlap');
};


