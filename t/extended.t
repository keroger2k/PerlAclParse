use strict;
use warnings;
use Test::More tests => 5;

BEGIN { use_ok('AccessList::Extended'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended', 'new');

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 3;
  my $p = AccessList::Extended->new;
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
  is($p->get_line_count(), 0, 'should return line count for acl');
};

subtest 'testing get_line_count for an non empty acl' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
  is($p->get_line_count(), 7887, 'should return line count for acl');
};