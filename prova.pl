#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::PKCS7;

my $openssl = new OpenCA::OpenSSL;
$openssl->setParams ( SHELL=>"/usr/local/ssl/bin/openssl",
		      CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf",
		      VERIFY=>"/usr/local/ssl/bin/verify",
		      SIGN=>"/usr/local/ssl/bin/sign" );

## $openssl->setParams ( STDERR => "/dev/null" );

my $signature = new OpenCA::PKCS7( SHELL=>$openssl,
				   INFILE=>"TEXT.sig",
				   DATAFILE=>"TEXT",
				   CA_CERT=>"cacert.pem");

if ( not $signature ) {
	print "Error\n";
	exit;
}

my $info =  $signature->getSigner();
my $info =  $signature->verifyChain();

print "Depth: 0\n";
print "Serial: " . $info->{0}->{SERIAL} . "\n";
print "E-Mail: " . $info->{0}->{EMAIL} . "\n";
print "C-Name: " . $info->{0}->{CN} . "\n";

print "Depth: 1\n";
print "Serial: " . $info->{1}->{SERIAL} . "\n";
print "E-Mail: " . $info->{1}->{EMAIL} . "\n";
print "C-Name: " . $info->{1}->{CN} . "\n";

print "Depth: 2\n";
print "Serial: " . $info->{2}->{SERIAL} . "\n";
print "E-Mail: " . $info->{2}->{EMAIL} . "\n";
print "C-Name: " . $info->{2}->{CN} . "\n";

exit 0; 

