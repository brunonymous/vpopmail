#!/usr/bin/perl
#
# this program will read users and password  from a file
# that is separated by ":" colons
#
# Thanks to "Jürgen Hoffmann" <jh@byteaction.de>

use IO::File;

my $fh=new IO::File;
$fh->open("user.dat");
while(<$fh>) {
        chop;
        my ($username,$password) = split/:/; 
# I am assuming they are seperated by colons
        system("~vpopmail/bin/vadduser","$username\@domain.tld","$password");
$fh->close;
