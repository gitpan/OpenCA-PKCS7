## OpenCA::PKCS7
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##

use strict;

package OpenCA::PKCS7;

$OpenCA::PKCS7::VERSION = '0.3.0a';

my %params = (
	 inFile => undef,
	 signature => undef,
	 dataFile => undef,
	 caCert => undef,
	 caDir => undef,
	 signer => undef,
	 context => undef,
	 backend => undef,
);

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };
	my $tmp;

        $self->{datafile}   = $keys->{DATAFILE};
        $self->{signature}  = $keys->{SIGNATURE};

        $self->{caCert}     = $keys->{CA_CERT};
        $self->{caDir}      = $keys->{CA_DIR};
        $self->{dataFile}   = $keys->{DATAFILE};

	$self->{inFile}	    = $keys->{INFILE};

	$self->{backend}    = $keys->{SHELL};

	if( $self->{inFile} ) {
		$self->{signature} = "";

		open(FD, "<$self->{inFile}" ) or return;
		while ( $tmp = <FD> ) {
			$self->{signature} .= $tmp;
		}
		close(FD);

	};

	return if (not $self->initSignature() );

        return $self;
}

sub initSignature {
	my $self = shift;
	my $keys = { @_ };
	my $tmp;

	return if ( (not $self->{inFile}) and ( not $self->{signature}));

	return 1;
}

sub getSigner {
	my $self = shift;

	my $keys = { @_ };
	my ( $tmp, $ret );
	
	if ( $self->{inFile} ) {
		$tmp=$self->{backend}->verify( SIGNATURE_FILE=>$self->{inFile},
					       NOCHAIN=>1,
					       DATA_FILE=>$self->{dataFile},
					       VERBOSE=>1 );
	} else {
		$tmp=$self->{backend}->verify( SIGNATURE=>$self->{signature},
					       NOCHAIN=>1,
					       DATA_FILE=>$self->{dataFile},
					       VERBOSE=>1 );
	};

	if ( not $ret = $self->parseDepth( DEPTH=>"0", DATA=>$tmp ) ) {
		return;
	}

	return $ret;
}

sub verifyChain {
	my $self = shift;

	my $keys = { @_ };
	my ( $tmp, $ret );

	if ( $self->{inFile} ) {
		$tmp=$self->{backend}->verify( SIGNATURE_FILE=>$self->{inFile},
					       DATA_FILE=>$self->{dataFile},
					       CA_CERT=>$self->{caCert},
					       CA_DIR=>$self->{caDir},
					       VERBOSE=>1 );
	} else {
		$tmp=$self->{backend}->verify( SIGNATURE=>$self->{signature},
					       DATA_FILE=>$self->{dataFile},
					       CA_CERT=>$self->{caCert},
					       CA_DIR=>$self->{caDir},
					       VERBOSE=>1 );
	};

	## return if ( $? != 0 );

	if ( not $ret = $self->parseDepth( DEPTH=>"0", DATA=>$tmp ) ) {
		return;
	}

	return $ret;
}

sub parseDepth {

	my $self = shift;
	my $keys = { @_ };

	my $depth = $keys->{DEPTH};
	my $data  = $keys->{DATA};
	my @dnList = ();
	my @ouList = ();

	my ( $serial, $dn, $email, $cn, @ou, $o, $c );
	my ( $currentDepth, $tmp, $line, $ret );
	
	return if (not $data);

	my @lines = split ( /(\n|\r)/ , $data );

	while( $line = shift @lines ) {
		( $currentDepth ) = ( $line =~ /Depth: (.*)/ )
			if( $line =~ /Depth:/ );

		if ( $line =~ /Serial Number:/ ) {
        		( $ret->{$currentDepth}->{SERIAL} ) = 
				( $line =~ /Serial Number:[^x]*.([^\)]+)/i);

			if ( length( $ret->{$currentDepth}->{SERIAL}) % 2 ) {
				$ret->{$currentDepth}->{SERIAL} = 
					"0" . $ret->{$currentDepth}->{SERIAL};
			}

		}

		if ( $line =~ /Subject:/ ) {
        		( $ret->{$currentDepth}->{DN} ) = 
				( $line =~ /Subject: ([^\n]+)/i );

			## Split the Subject into separate fields
			@dnList = split( /[\,\/]+/, $dn );
			@ouList = ();

			$dn = $ret->{$currentDepth}->{DN};
			my $tmpOU;

			( $ret->{$currentDepth}->{EMAIL} ) =
				 ( $dn =~ /Email=([^\,^\/]+)/i );
        		( $ret->{$currentDepth}->{CN} ) = 
				( $dn =~ /CN=([^\,^\/]+)/i );

			## Analyze each field
			foreach $tmp (@dnList) {
				next if ( not $tmp );

				## The OU variable is a list
				if( $tmp =~ /OU=/i ) {
					( $tmpOU ) = ( $tmp =~ /OU=(.*)/i );
					push @ouList, $tmpOU;
				}
			}

			$ret->{$currentDepth}->{OU} = [ @ouList ];

		       	( $ret->{$currentDepth}->{L} ) =
				( $dn =~ /L=([^\,^\/]+)/i );

		       	( $ret->{$currentDepth}->{O} ) = 
				( $dn =~ /O=([^\,^\/]+)/i );

		       	( $ret->{$currentDepth}->{C} ) =
				( $dn =~ /C=([^\,^\/]+)/i );
		}
	}

	return $ret;
}

sub getSignature {
	my $self = shift;

	return if( not $self->{signature} );
	return $self->{signature};
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__

# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::PKCS7 - Perl extension for basic handling PKCS#7 Signatures.

=head1 SYNOPSIS

use OpenCA::PKCS7;

=head1 DESCRIPTION

This module contains all functions needed for handling PKCS#7
signatures. It requires some parameters to be passed such as
a reference to a OpenCA::OpenSSL instance. 
 
This module provides an interface to PKCS#7 structures, no specific
crypto functions are performed (see the OpenCA::OpenSSL module
for this).

=head1 FUNCTIONS

=head2 sub new () - Create a new instance of the Class.

	This function creates an instance of the module. If you
	provide a certificate it will be parsed and stored in
	local variable(s) for later usage. The function will return
	a blessed reference.

	Accepted parameters are:

		SHELL       - Reference to an initialized
			      OpenCA::OpenSSL instance;
		INFILE      - Signature File;
		SIGNATURE   - Signature Data;
		DATAFILE    - Data File(*);
		CA_CERT     - CA Certificate File to check chain
                              Depth ( >0 )(*);
		CA_DIR	    - CA Certificates directory to check
			      chain Depth ( >0 );

	(*) - Optional parameter.

	EXAMPLE:

	      $x509 = new OpenCA::PKCS#7( SHELL=>$crypto,
					  INFILE=>"TEXT.sig",
					  DATA=>"TEXT",
					  CACERT=>"/OpenCA/cacert.pem");

=head2 sub getSigner () - Get basic Signer Infos.

=head2 sub verifyChain () - Get and Verify basic signer Infos (CAcert needed).

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::CRL, OpenCA::REQ, OpenCA::X509

=cut
