#!/usr/local/bin/perl -w
use strict;
use lib '../..';
use FileHandle::Deluxe ':all';
$ENV{'PATH'} = '';
use Test;

BEGIN { plan tests => 3 };


my $dat = 'data.txt';
my ($tainted_path);


#------------------------------------------------------
# basic object creation and writing
# 
{
	my $fh = FileHandle::Deluxe->new($dat, write=>1, allow_insecure_code=>1);
	
	unless (print $fh $dat) {
		ok(0);
		exit;
	}
	
	ok(1);
}
# 
# basic object creation and writing
#------------------------------------------------------


#------------------------------------------------------
# read using auto_chomp
# 
{
	my $fh = FileHandle::Deluxe->new($dat, auto_chomp=>1, allow_insecure_code=>1);
	$tainted_path = <$fh>;
	err_comp('read', $tainted_path, $dat);
}
# 
# read using auto_chomp
#------------------------------------------------------


#------------------------------------------------------
# open using safe_dir
# 
{
	my $fh = FileHandle::Deluxe->new($tainted_path, safe_dir=>'.', allow_insecure_code=>1);
	$tainted_path = <$fh>;
	err_comp('read', $tainted_path, $dat);
}
# 
# open using safe_dir
#------------------------------------------------------


# unlink test data file
unlink($dat) or die "cannot unlink data file: $!";


#------------------------------------------------------
# err_comp
#
sub err_comp {
	my ($testname, $is, $should) = @_;
	
	if($is ne $should) {
		$testname ||= 'fail';
		
		print STDERR 
			"\n", $testname, "\n",
			"\tis:     $is\n",
			"\tshould: $should\n\n";	
		ok(0);
		exit;
	}
	
	ok(1);
}
#
# err_comp
#------------------------------------------------------

