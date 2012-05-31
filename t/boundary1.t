use strict;
use warnings;
use Test::More tests => 13;
use Test::Harness;
use AccessList::Parser;

BEGIN { use_ok('AccessList::Extended::Boundary1'); }
BEGIN { use_ok('ConfigParse::ParseIOS'); }

can_ok('AccessList::Extended::Boundary1', 'new');

my $parser = AccessList::Parser->new;

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
  shift(@latest_acl);
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
  is($p->get_line_count(), 7861, 'should return line count for acl');
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
  is($p->get_line_count(), 7829, 'should return line count for acl');
};

subtest 'testing parsed_acl' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'parsed_acl');
  my @result = $p->parsed_acl();
  is(scalar @result, 7861, 'should return the entire ACL parsed');
};

subtest 'testing parsed_acl_section' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'parsed_acl_section');
  my @result = $p->parsed_acl_section(4);
  is(scalar @result, 594, 'should return just section 4 parsed');
};

subtest 'testing normalize_parsed_array' => sub {
  plan tests => 2;
  
  my $p = arrange();
  
  can_ok('AccessList::Extended::Boundary1', 'normalize_parsed_array');
  my @acl = $p->parsed_acl();
  #my @result = $p->normalize_parsed_array(@acl);
  is(scalar @acl, 7861, 'should return just section 4 parsed');
};


# subtest 'testing b1 acl section 3' => sub {
#   plan tests => 2;

#   my $p = arrange();
#     can_ok('AccessList::Extended::Boundary1', 'check_rules_overlap');

#   my $result = $p->check_rules_overlap($p->parsed_acl_section(3));

#   is(scalar keys %$result, 29, 'shoquld return overlaps from section 3 of B1 access list');
# };

# subtest 'testing check_all_sections_for_overlap' => sub {
#   plan tests => 2;
  
#   my $p = arrange();
  
#   can_ok('AccessList::Extended::Boundary1', 'check_all_sections_for_overlap');
#   my $result = $p->check_all_sections_for_overlap();

#   is(scalar keys %$result, 273, 'shoquld return overlaps from all sections of B1 access list');
# };



