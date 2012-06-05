#!/usr/bin/perl -w

use strict;
use ConfigParse::ParseIOS;
use AccessList::Parser;
use AccessList::Extended;


my $extended = AccessList::Extended->new;
my $parser = AccessList::Parser->new;

my $file = "";
my @file_array = ();
my @parsed_rules = ();


die unless (@ARGV);

while (@ARGV) {
	if ($ARGV[0] eq '-f' && $ARGV[1] && $ARGV[1] !~ /^-.*/) {
		$file = $ARGV[1];
		shift @ARGV; shift @ARGV;
		last;
	}

	print "\nSyntax:\n main.pl {-f file} \n ";
	exit(0);
}

open (LIST, $file) || die "$file could not be opened: $!\nPlease check the file.\n";

while(my $line = <LIST>){
  $line =~ s/\r\n$//g; #strip CRLF
  push @file_array, $line;
}
close(LIST);

my $config = ConfigParse::ParseIOS->new(file => \@file_array);
my %acls = $config->parse_acls();
my @result = $config->get_version(\%acls, 'b1acl-in-');
my @latest_acl = @{$acls{"b1acl-in-$result[0]"}};

shift(@latest_acl); #remove first line, just get rules.

foreach my $line (@latest_acl){
	push @parsed_rules, $parser->parse($line);
}

my $overlaps = $extended->check_rules_overlap(@parsed_rules);

foreach(keys %{$overlaps}) {
	print "Entry: $_\n";
	foreach my $line (@{$overlaps->{$_}}){
		print "\t$line\n";
	}
}


