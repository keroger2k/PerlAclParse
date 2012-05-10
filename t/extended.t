use strict;
use warnings;
use Test::More tests => 5;

BEGIN { use_ok('AccessList::Extended'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended', 'new');

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

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 3;
  my $p = AccessList::Extended->new;
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
  is($p->get_line_count(), 0, 'should return line count for acl');
};

subtest 'testing get_line_count for an non empty acl' => sub {
  plan tests => 3;
  my $config = arrange();
  my %acls = $config->parse_acls();
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

  my $p = AccessList::Extended->new(rules => \@latest_acl);
  isa_ok($p, 'AccessList::Extended');
  can_ok('AccessList::Extended', 'get_line_count');
  is($p->get_line_count(), 7887, 'should return line count for acl');
};