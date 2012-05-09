use strict;
use warnings;
use Test::More tests => 5;

BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('ConfigParse::ParseIOS', 'new');

subtest 'test parse_acls' => sub {
  plan tests => 2;
  my $p = ConfigParse::ParseIOS->new;
  my @file = $p->open_file('tmp/acl-1.txt');
  my %result = $p->parse_acls(@file);
  my @b1_acl = @{$result{'NMCI_B1_VPN_OUT_v1'}};
  is(scalar keys %result, 9, 'should get a hash of 9 acls');
  is_deeply(\@b1_acl, [
    'ip access-list extended NMCI_B1_VPN_OUT_v1',
    ' permit esp 138.163.128.64 0.0.0.15 any',
    ' permit udp 138.163.128.64 0.0.0.15 any eq isakmp',
    ' permit udp 138.163.128.64 0.0.0.15 eq isakmp any',
    ' deny   ip any any log'], 'correctly parse acl into an array in a hash');
};

subtest 'test get_version for acl' => sub {
  plan tests => 1;
  my $p = ConfigParse::ParseIOS->new;
  my @file = $p->open_file('tmp/acl-1.txt');
  my %acls = $p->parse_acls(@file);
  my @result = $p->get_version(\%acls, 'b1acl-in-');
  is_deeply(\@result, [
    '1132',
    '1131'], 'correct returns all names of acl sent');
};

subtest 'test correctly get the latest version of acl' => sub {
  plan tests => 1;
  my $p = ConfigParse::ParseIOS->new;
  my @file = $p->open_file('tmp/acl-1.txt');
  my %acls = $p->parse_acls(@file);
  my @result = $p->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};
  is(scalar @latest_acl, 7887, 'something')
};