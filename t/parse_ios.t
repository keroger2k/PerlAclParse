use strict;
use warnings;
use Test::More tests => 5;

BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('ConfigParse::ParseIOS', 'new');

sub  arrange {
  my @file_array = ();
  my $path = 'tmp/acl-1.txt';
  open (LIST, $path) || die "$path could not be opened: $!\nPlease check the file.\n";
  while(my $line = <LIST>){
    $line =~ s/\r\n$//g; #strip CRLF
    push @file_array, $line;
  }
  close(LIST);
  return ConfigParse::ParseIOS->new(file => \@file_array);
}

subtest 'test parse_acls' => sub {
  plan tests => 2;
  my $p = arrange();
  my %result = $p->parse_acls();
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
  my $p = arrange();
  my %acls = $p->parse_acls();
  my @result = $p->get_version(\%acls, 'b1acl-in-');
  is_deeply(\@result, [
    '1132',
    '1131'], 'correct returns all names of acl sent');
};

subtest 'test correctly get the latest version of acl' => sub {
  plan tests => 1;
  my $p = arrange();
  my %acls = $p->parse_acls();
  my @result = $p->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};
  is(scalar @latest_acl, 7862, 'something')
};