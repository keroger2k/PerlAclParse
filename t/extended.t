use strict;
use warnings;
use Test::More tests => 4;

BEGIN { use_ok('AccessList::Extended'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended', 'new');

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 2;
  my $p = AccessList::Extended->new;
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
};

