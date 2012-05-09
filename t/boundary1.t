use strict;
use warnings;
use Test::More tests => 9;
use Test::Harness;

BEGIN { use_ok('AccessList::Extended::Boundary1'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended::Boundary1', 'new');

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 3;
  my $p = AccessList::Extended::Boundary1->new;
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_line_count');
  is($p->get_line_count(), 0, 'should return line count for acl');
};

subtest 'testing get_line_count for an non empty acl' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended::Boundary1->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_line_count');
  is($p->get_line_count(), 7887, 'should return line count for acl');
};

subtest 'testing get_acl_section first section' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended::Boundary1->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(1), 34, 'should return section one of b1 acl');
};

subtest 'testing get_acl_section last section' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended::Boundary1->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(8), 2, 'should return section eight of b1 acl');
};

subtest 'testing get_acl_section section that does not exist' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended::Boundary1->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(9), 0, 'should return and empty array');
};

subtest 'testing replace_section with an empty array of rules' => sub {
  plan tests => 3;
  my $config = ConfigParse::ParseIOS->new;
  my @file = $config->open_file('tmp/acl-1.txt');
  my %acls = $config->parse_acls(@file);
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended::Boundary1->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'replace_section');
  is(scalar $p->replace_section(1), 0, 'should return an unchanged acl');
};
