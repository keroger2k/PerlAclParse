use strict;
use warnings;
use Test::More tests => 6;

BEGIN { use_ok('AccessList::Extended'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended', 'new');

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 2;
  my $p = AccessList::Extended->new;
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
};


subtest 'testing check_rules_overlap' => sub {
 plan tests => 2;
 my $p = IPAddressv4::IPHelp->new;
 can_ok('IPAddressv4::IPHelp', 'check_rules_overlap');

 my @sent = (
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => 'any',
      'acl_dst_ip'   => '10.0.0.0 255.255.255.0',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => '10.0.0.0 0.0.1.255',
      'acl_dst_ip'   => 'any',
    },
    {
      'acl_action '  => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => '10.0.1.0 0.0.0.255',
      'acl_dst_ip'   => 'any',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => '10.0.2.0 0.0.0.255',
      'acl_dst_ip'   => 'any',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => '10.0.2.1',
      'acl_dst_ip'   => 'any',
    },
  );

 my $result = $p->check_rules_overlap(@sent);
 my %expected = (
  '10.0.0.0 255.255.0.0' =>
            ['10.0.0.0 255.255.255.224', '10.0.0.32 255.255.255.224',
             '10.0.0.64 255.255.255.224', '10.0.0.0 255.255.254.0',
             '10.0.3.0 255.255.255.0'],
  '10.0.0.0 255.255.254.0' =>
            ['10.0.0.0 255.255.255.224', '10.0.0.32 255.255.255.224',
             '10.0.0.64 255.255.255.224']);
 
 is_deeply(\%$result, \%expected, 'yea baby');
};

