use strict;
use ExtUtils::MakeMaker;

WriteMakefile(
  'NAME'=>'Parse-Acl',
  'VERSION_FROM' => 'bin/main.pl',
  'PREREQ_PM' => {
  },
  'EXE_FILES' => [('bin/main.pl')]
);
