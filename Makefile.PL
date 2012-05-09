use strict;
use ExtUtils::MakeMaker;

WriteMakefile(
  'NAME'=>'CLIE',
  'VERSION_FROM' => 'bin/main.pl',
  'PREREQ_PM' => {
  },
  'EXE_FILES' => [('bin/main.pl')]
);
