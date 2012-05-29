use strict;
use warnings;
use AccessList::Extended;
use Test::More tests => 8;

BEGIN { use_ok('AccessList::Extended'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended', 'new');

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 2;
  my $p = AccessList::Extended->new;
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
};
#
# Check Overlap 1
#


subtest 'check overlap 1' => sub {
 plan tests => 2;
 my $p = AccessList::Extended->new;
 can_ok('AccessList::Extended', 'check_rules_overlap');

 my @sent = (
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => 'any',
      'acl_dst_ip'   => '10.0.0.0 0.0.0.255',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_src_ip'   => 'any',
      'acl_dst_ip'   => '10.0.0.0 0.0.1.255',
    }
  );

 my $result = $p->check_rules_overlap(@sent);
 my %expected = (
  'permit ip any 10.0.0.0 0.0.1.255' =>
            ['permit ip any 10.0.0.0 0.0.0.255']  );
 
 is_deeply(\%$result, \%expected, 'testing check_rules_overlap where destination addresses overlap');
};

#
# Check Overlap 2
#

subtest 'check overlap 2' => sub {
 plan tests => 2;
 my $p = AccessList::Extended->new;
 can_ok('AccessList::Extended', 'check_rules_overlap');

 my @sent = (
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => 'any',
      'acl_src_ip'   => '10.0.0.0 0.0.0.255',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => 'any',
      'acl_src_ip'   => '10.0.0.0 0.0.1.255',
    }
  );

 my $result = $p->check_rules_overlap(@sent);
 my %expected = (
  'permit ip 10.0.0.0 0.0.1.255 any' =>
            ['permit ip 10.0.0.0 0.0.0.255 any']  );
 
 is_deeply(\%$result, \%expected, 'testing check_rules_overlap where source addresses overlap');
};


#
# Check Overlap 3
#

subtest 'check overlap 3' => sub {
 plan tests => 2;
 my $p = AccessList::Extended->new;
 can_ok('AccessList::Extended', 'check_rules_overlap');

 my @sent = (
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => 'any',
      'acl_src_ip'   => '10.0.1.3',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => 'any',
      'acl_src_ip'   => '10.0.0.0 0.0.1.255',
    }
  );

 my $result = $p->check_rules_overlap(@sent);
 my %expected = (
  'permit ip 10.0.0.0 0.0.1.255 any' =>
            ['permit ip host 10.0.1.3 any']  );
 
 is_deeply(\%$result, \%expected, 'testing check_rules_overlap where source addresses overlap with host entry');
};

#
# Check Overlap 4
#

subtest 'check overlap 4' => sub {
 plan tests => 2;
 my $p = AccessList::Extended->new;
 can_ok('AccessList::Extended', 'check_rules_overlap');

 my @sent = (
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => '10.0.1.3',
      'acl_src_ip'   => 'any',
    },
    {
      'acl_action'   => 'permit',
      'acl_protocol' => 'ip',
      'acl_dst_ip'   => '10.0.0.0 0.0.1.255',
      'acl_src_ip'   => 'any',
    }
  );

 my $result = $p->check_rules_overlap(@sent);
 my %expected = (
  'permit ip any 10.0.0.0 0.0.1.255' =>
            ['permit ip any host 10.0.1.3']  );
 
 is_deeply(\%$result, \%expected, 'testing check_rules_overlap where destination addresses overlap with host entry');
};

