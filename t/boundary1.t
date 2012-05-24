use strict;
use warnings;
use Test::More tests => 11;
use Test::Harness;

BEGIN { use_ok('AccessList::Extended::Boundary1'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended::Boundary1', 'new');

sub arrange {
  my @file_array = ();
  my $path = 'tmp/acl-1.txt';
  open (LIST, $path) || die "$path could not be opened: $!\nPlease check the file.\n";
  while(my $line = <LIST>){
    $line =~ s/\r\n$//g; #strip CRLF
    push @file_array, $line;
  }
  close(LIST);
  my $config = ConfigParse::ParseIOS->new(file => \@file_array);
  my %acls = $config->parse_acls();
  my @result = $config->get_version(\%acls, 'b1acl-in-');
  my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};
  return AccessList::Extended::Boundary1->new(rules => \@latest_acl);
}

subtest 'testing get_line_count for an empty acl' => sub {
  plan tests => 3;

  my $p = AccessList::Extended::Boundary1->new;
  
  isa_ok($p, 'AccessList::Extended::Boundary1');
  can_ok('AccessList::Extended::Boundary1', 'get_line_count');
  is($p->get_line_count(), 0, 'should return line count for acl');
};

subtest 'testing get_line_count for an non empty acl' => sub {
  plan tests => 2;
  
  my $p = arrange();

  can_ok('AccessList::Extended::Boundary1', 'get_line_count');
  is($p->get_line_count(), 7887, 'should return line count for acl');
};

subtest 'testing get_acl_section first section' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(1), 34, 'should return section one of b1 acl');
};

subtest 'testing get_acl_section last section' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(8), 2, 'should return section eight of b1 acl');
};

subtest 'testing get_acl_section section that does not exist' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'get_acl_section');
  is(scalar $p->get_acl_section(9), 0, 'should return and empty array');
};

subtest 'testing replace_section with an empty array of rules' => sub {
  plan tests => 2;
  
  my $p = arrange();
  my @current_section = $p->get_acl_section(1);
  $p->replace_section(1, ());
  my @updated_section = $p->get_acl_section(1);
  
  can_ok('AccessList::Extended::Boundary1', 'replace_section');
  is_deeply(\@updated_section, \@current_section, 'should return an unchanged acl');
};

subtest 'testing replace_section with a new set of rules' => sub {
  plan tests => 3;
  
  my $p = arrange();
  my @new_rules = (
    ' remark Section 1 -- Routing Protocol Permits',
    ' deny ip any any'); 
  $p->replace_section(1, @new_rules);
  my @new_section = $p->get_acl_section(1);
  
  can_ok('AccessList::Extended::Boundary1', 'replace_section');
  is_deeply(\@new_section, \@new_rules, 'section should have been replaced with new rules');
  is($p->get_line_count(), 7855, 'should return line count for acl');
};

subtest 'testing read_acl section' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'read_acl');
  my @section = $p->get_acl_section(4);
  my @result = $p->read_acl(@section);
  is(scalar $p->get_acl_section(9), 0, 'should return and empty array');
};

