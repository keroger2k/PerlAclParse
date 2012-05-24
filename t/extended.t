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

subtest 'testing get_acl_source_values for an empty acl' => sub {
  plan tests => 2;
  my $p = AccessList::Extended->new;
  can_ok('AccessList::Extended', 'get_acl_source_values');
  my @sent = ();
  my @results = $p->get_acl_source_values(@sent);
  my @expected = ();
  is_deeply(\@results, \@expected, 'sending get_acl_source_values an empty array will return return an empty array');
};

subtest 'testing parse_rule a permit ip any host rule' => sub {
  plan tests => 2;
  my $p = AccessList::Extended->new;
  can_ok('AccessList::Extended', 'parse_rule');
  my @sent = 'permit ip any host 205.93.33.21';
  my %results = $p->parse_rule(@sent);
  my %expected = (
  	'acl_action' => 'permit',
  	'protocol' => 'ip'
  	);
  is_deeply(\%results, \%expected, 'correctly parsed permit ip any host acl rule');
};

# subtest 'testing get_acl_source_values for a non-empty acl' => sub {
#   plan tests => 2;
#   my $p = AccessList::Extended->new;
#   can_ok('AccessList::Extended', 'get_acl_source_values');
#   my @sent = (
#   	'remark Section 1 -- Routing Protocol Permits',
#  	'remark', 
#  	'permit tcp host 214.40.4.237 host 214.40.4.238 eq bgp',
#  	'permit tcp host 214.40.4.237 eq bgp host 214.40.4.238',
#  	'permit tcp host 192.168.255.113 host 192.168.255.114 eq bgp'
#  	);

#   my @results = $p->get_acl_source_values(@sent);
#   my @expected = (
#   	'214.40.4.237 255.255.255.255',
#   	'214.40.4.237 255.255.255.255',
#   	'192.168.255.113 255.255.255.255'
#   	);
#   is_deeply(\@results, \@expected, 'sending get_acl_source_values an empty array will return return an empty array');
# };

