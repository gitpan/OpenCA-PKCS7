#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::PKCS7;

my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/bin/openssl" );
$openssl->setParams ( CONFIG=>"/usr/ssl/openssl.cnf",
		      VERIFY=>"/usr/bin/verify",
		      SIGN=>"/usr/bin/sign" );

## $openssl->setParams ( STDERR => "/dev/null" );

my $signature = new OpenCA::PKCS7( SHELL=>$openssl,
				   INFILE=>"TEXT.sig",
				   DATAFILE=>"TEXT",
				   CA_CERT=>"cacert.pem",
				   CA_DIR=>"chain");

if ( not $signature ) {
	print "Error\n";
	exit;
}

my $info =  $signature->getSigner();
my $info =  $signature->verifyChain();

foreach $level ( keys %$info ) {
	print "Depth: $level\n";
	print "    Serial: " . $info->{0}->{SERIAL} . "\n";
	print "    E-Mail: " . $info->{0}->{EMAIL} . "\n";
	print "    C-Name: " . $info->{0}->{CN} . "\n";
	print "\n";
};

exit 0; 

