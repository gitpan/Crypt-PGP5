#!/usr/bin/perl -w
#
# Crypt::PGP5 - A module for accessing PGP 5 functionality.
# $Id: PGP5.pm,v 1.23 2000/03/02 08:01:45 hash Exp hash $
# Copyright (c) 1999-2000 Ashish Gulhati. All Rights Reserved.

package Crypt::PGP5;

use 5.004;
$VERSION = 1.23;

use Fcntl;
use Expect;
use vars qw($VERSION);
use POSIX qw(tmpnam);

sub new {
  bless { PASSPHRASE     =>   0,
	  ARMOR          =>   1,
	  DETACH         =>   1,
	  SECRETKEY      =>   0,
	  DEBUG          =>   1,
	  VERSION        =>   'Version: Crypt::PGP5',
	}, shift;
}

sub AUTOLOAD {
  my $self = shift; my $auto = $AUTOLOAD; $auto =~ s/.*:://;
  $auto =~ /^(passphrase|secretkey|armor|detach|version|debug)$/ and $self->{"\U$auto"} = shift;
}

sub sign {
  my $self = shift; my ($secretkey, $detach, $armor) = ();
  my $detach = "-b" if $self->{DETACH}; my $armor = "-a" if $self->{ARMOR}; 
  my $secretkey = "-u " . $self->{SECRETKEY} if $self->{SECRETKEY};
  my $expect = Expect->spawn ("pgps $armor $detach $secretkey"); $expect->log_stdout($self->{DEBUG});
  my $message = join ('', @_); $message .= "\n" unless $message =~ /\n$/s;
  $expect->expect (undef, "No files specified."); sleep 1; print $expect ("$message\x04"); 
  $expect->expect (undef, 'Enter pass phrase:'); sleep 1; print $expect "$self->{PASSPHRASE}\r";
  $expect->expect (undef, '-re', 'Pass phrase is good.\s*'); sleep 1; $expect->expect (undef);
  my $info = $expect->exp_before(); $info =~ s/^Version: .*/$self->{VERSION}/mg if $self->{VERSION}; 
  $info =~ s/\r\n/\n/sg; return $info;
}

sub verify {
  my $self = shift;
  my $expect = Expect->spawn ("pgpv"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "No files specified."); sleep 1; print $expect (@_,"\x04"); 
  $expect->expect (undef, '-re', 'type binary.\s*', '-re', 'pass phrase:\s*');
  if ($expect->exp_match_number==2) {
    sleep 1; print $expect "$self->{PASSPHRASE}\r";
    $expect->expect (undef, '-re', 'type binary.\s*');
  }
  sleep 1; $expect->expect (undef); my $info = $expect->exp_before();
  my $trusted = ($info !~ /WARNING: The signing key is not trusted/s);
  return $info unless $info =~ /^(.*)(Good|BAD)\ signature\ made\ (\S+\s+\S+\s+\S+)\ by\ key:
		  \s+(\S+)\s+bits,\ Key\ ID\ (\S+),\ Created\ (\S+)\s+\"([^\"]+)\"/sx;
  return ($2, $7, $5, $3, $6, $4, $trusted, $1);
}

sub dverify {
  my $self = shift;
  my $message = join '', @{$_[0]}; my $signature = join '', @{$_[1]};
#  $message =~ s/\n/\r\n/sg;
  my $tmpnam; do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  my $tmpnam2; do { $tmpnam2 = tmpnam() } until sysopen(FH2, $tmpnam2, O_RDWR|O_CREAT|O_EXCL);
  print FH $signature; close FH; print FH2 $message; close FH2;
  my $expect = Expect->spawn ("pgpv $tmpnam"); $expect->log_stdout($self->{DEBUG});
  $expect->expect(undef, "File to check signature against"); sleep 1;
  print $expect "$tmpnam2\r"; sleep 1; $expect->expect(undef); my $info = $expect->exp_before();
  my $trusted = ($info !~ /WARNING: The signing key is not trusted/s);
  return undef unless $info =~ /(Good|BAD)\ signature\ made\ (\S+\s+\S+\s+\S+)\ by\ key:
		  \s+(\S+)\s+bits,\ Key\ ID\ (\S+),\ Created\ (\S+)\s+\"([^\"]+)\"/sx;
  unlink $tmpnam; unlink $tmpnam2; 
  return ($1, $6, $4, $2, $5, $3, $trusted, $message);
}

sub msginfo {
  my $self = shift; my @return = ();
  my $home = $ENV{'HOME'}; $ENV{'HOME'} = '/dev/null';
  my $expect = Expect->spawn ("pgpv"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "No files specified."); sleep 1; print $expect (@_,"\x04"); 
  sleep 1; $expect->expect (undef); my $info = $expect->exp_before();
  $info =~ s/Key ID (0x.{8})/{push @return, $1}/sge; $ENV{'HOME'} = $home; 
  return @return;
}

sub encrypt {
  my $self = shift; my $recipients = shift;
  my $armor = "-a" if $self->{ARMOR}; my $rcpts = join ( ' ', map "-r$_", @{ $recipients } );
  my $expect = Expect->spawn ("pgpe $armor $rcpts"); $expect->log_stdout($self->{DEBUG});
  my $message = join ('',@_); $message .= "\n" unless $message =~ /\n$/s; 
  $expect->expect (undef, "No files specified."); sleep 1; print $expect ("$message\x04"); 
  $message =~ /\n(\S*)\s*$/s; $expect->expect (undef, $1); sleep 1; $expect->expect (undef); 
  my $info = $expect->exp_before(); $info =~ s/.*\n(-----BEGIN)/$1/s;
  $info =~ s/\r\n/\n/sg; return $info;
}

sub addkey {
  my $self = shift; my $key = shift; my $tmpnam;
  do { $tmpnam = tmpnam() } until sysopen(FH, $tmpnam, O_RDWR|O_CREAT|O_EXCL);
  print FH $key; close FH;
  my $expect = Expect->spawn ("pgpk -a $tmpnam"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "to your keyring? [Y/n]"); my $info = $expect->exp_before(); 
  sleep 1; print $expect ("\r"); sleep 1; $expect->expect (undef); unlink $tmpnam;
  $info =~ s/.*Key ring:[^\n]*\n(.*found\s*\n).*/$1/s; my @r = split (/\r/, $info); 
  return parsekeys (@r);
}

sub delkey {
  my $self = shift; my $key = shift;
  my $expect = Expect->spawn ("pgpk -r $key"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "[y/N]? "); my $info = $expect->exp_before(); 
  sleep 1; print $expect ("y\r"); sleep 1; $expect->expect (undef);
}

sub disablekey {
  my $self = shift; my $key = shift;
  my $keyinfo = $self->keyinfo($key);
  return if ${$keyinfo}{Type} =~ /\@$/;
  my $expect = Expect->spawn ("pgpk -d $key"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "[y/N] "); my $info = $expect->exp_before(); 
  sleep 1; print $expect ("y\r"); sleep 1; $expect->expect (undef);
}

sub enablekey {
  my $self = shift; my $key = shift;
  my $keyinfo = $self->keyinfo($key);
  return unless ${$keyinfo}{Type} =~ /\@$/;
  my $expect = Expect->spawn ("pgpk -d $key"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, "[y/N] "); my $info = $expect->exp_before(); 
  sleep 1; print $expect ("y\r"); sleep 1; $expect->expect (undef);
}

sub keylist {
  my $self = shift; my $userids = join (' ', @_); my @keylist = `pgpk -ll $userids`; 
  return parsekeys (@keylist);
}

sub parsekeys {
  my @keylist = @_;
  $keylist[0] = "\n"; pop @keylist; my $i=-1; 
  my @keys; my $subkey=0; my $sign; my $uid;
  my $newkey = undef;
  foreach (@keylist) {
    if ($newkey) {
      $sign=0; $uid=0;
      /(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)/;
      $keys[++$i] = { 
		     Type       =>    $1,
		     Bits       =>    $2,
		     ID         =>    $3,
		     Created    =>    $4,
		     Expires    =>    $5,
		     Algorithm  =>    $6,
		     Use        =>    $7
		    };
    }
    else {
      if (/^f16\s+Fingerprint16 = (.*)$/) {
	$keys[$i]{Fingerprint}  =     $1;
      }
      if (/^f20\s+Fingerprint20 = (.*)$/) {
	if ($subkey) {
	  $keys[$i]{Fingerprint2}  =     $1;
	  $subkey                  =     0;
	}
	else {
	  $keys[$i]{Fingerprint}   =     $1;
	}
      }
      elsif (/^sub\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/) {
	$subkey                    =     1;
	$keys[$i]{Bits2}           =     $1;
	$keys[$i]{ID2}             =     $2;
	$keys[$i]{Created2}        =     $3;
	$keys[$i]{Expires2}        =     $4;
	$keys[$i]{Algorithm2}      =     $5;
      }
      elsif (/^(sig|SIG)(.)\s+(\S+)\s+(\S+)\s+(.*)/) {
	push (@{$keys[$i]{SIGNS}}, 
	      {	ID    =>     $3,
		Date  =>     $4,
		UID   =>     $5
	      }
	     );
      }
      elsif (/^uid\s+(.*)/) {
	push (@{$keys[$i]{UIDS}}, $1);
      }
    }
    $newkey = /^$/;
  }
  return @keys;
}

sub keypass {
  my $self = shift; my ($keyid, $oldpass, $newpass) = @_;
  my $keyinfo = $self->keyinfo($keyid);
  return unless ${$keyinfo}{Type} =~ /^sec/;
  my $expect = Expect->spawn ("pgpk -e $keyid"); $expect->log_stdout($self->{DEBUG});
  $expect->expect (undef, '[y/N]? '); sleep 1; print $expect ("\r"); 
  $expect->expect (undef, '[y/N]? '); sleep 1; print $expect ("\r"); 
  $expect->expect (undef, '(y/N)? '); sleep 1; print $expect ("y\r"); 
  $expect->expect (undef, 'phrase: '); sleep 1; print $expect ("$oldpass\r"); 
  $expect->expect (undef, 'phrase: '); sleep 1; print $expect ("$newpass\r"); 
  $expect->expect (undef, 'phrase: '); sleep 1; print $expect ("$newpass\r"); 
  $expect->expect (undef, '[y/N]? '); sleep 1; print $expect ("y\r"); 
  sleep 1; $expect->expect (undef); my $info = $expect->exp_before();
  $info =~ /Keyrings updated.$/s;
}

sub extractkey {
  my $self = shift; my $userid = shift; my $keyring = shift; $keyring = "-o $keyring" if $keyring; 
  my $expect = Expect->spawn ("pgpk -x $armor \"$userid\" $keyring"); $expect->log_stdout($self->{DEBUG});
  sleep 1; $expect->expect (undef); my $info = $expect->exp_before();
}

sub keygen {
  my $self = shift; my ($name, $email, $keytype, $keysize, $expire, $pass) = @_;
  system ("pgpk -g +batchmode=1 $keytype $keysize \"$name <$email>\" $expire \"$pass\" >/dev/null 2>&1");
}

=pod

=head1 NAME 

Crypt::PGP5 - A module for accessing PGP 5 functionality.

=head1 SYNOPSIS

  use Crypt::PGP5;
  $pgp = new Crypt::PGP5;

  $pgp->secretkey ($keyid);              # Set numeric or symbolic ID of default secret key.
  $pgp->passphrase ($passphrase);        # Set passphrase.
  $pgp->armor ($boolean);                # Switch ASCII armoring on or off.
  $pgp->detach ($boolean);               # Switch detached signatures on or off.
  $pgp->version ($versionstring);        # Set version string
  $pgp->debug ($boolean);                # Switch debugging output on or off.

  @signed = $pgp->sign (@message);

  @recipients = $pgp->msginfo (@ciphertext);

  @ciphertext = $pgp->encrypt ([@recipients], @plaintext);

  @plaintext = $pgp->verify (@ciphertext);

  ($validity, $userid, $keyid, $signtime, $keytime, $keysize,
   $trusted, @plaintext) = $pgp->verify (@signedmessage);

  ($validity, $userid, $keyid, $signtime, $keytime, $keysize,
   $trusted, @plaintext) = $pgp->dverify (@signature, @message);

  $pgp->keygen ($name, $email, $keytype, $keysize, $expire, $ringdir);
  $pgp->keypass ($keyid, $oldpasswd, $newpasswd);
  $pgp->addkey ($keyring, @key);
  $pgp->delkey ($keyid);
  $pgp->disablekey ($keyid);
  $pgp->enablekey ($keyid);
  @keylist = $pgp->keylist ();
  @key = $pgp->extractkey ($userid, $keyring);

=head1 DESCRIPTION

The Crypt::PGP5 module provides near complete access to PGP 5
functionality through an object oriented interface. It provides
methods for encryption, decryption, signing, signature verification,
key generation, key export and import, and most other key management
functions.

=head1 CONSTRUCTOR

=over 2

=item B<new ()>

Creates and returns a new Crypt::PGP5 object.

=back

=head1 DATA METHODS

=over 2

=item B<secretkey ()>

Sets the B<SECRETKEY> instance variable which may be a KeyID or a
username. This is the ID of the default key which will be used for
signing.

=item B<passphrase ()>

Sets the B<PASSPHRASE> instance variable which is required for signing
and decryption.

=item B<armor ()>

Sets the B<ARMOR> instance variable. If set to 0, Crypt::PGP doesn't
ASCII armor its output. Else, it does. Default is to use
ascii-armoring. I haven't tested this without ASCII armoring yet.

=item B<detach ()>

Sets the B<DETACH> instance variable. If set to 1, the sign method
will produce detached signature certificates, else it won't.

=item B<version ()>

Sets the B<VERSION> instance variable which can be used to change the
Version: string on the PGP output to whatever you like.

=item B<debug ()>

Sets the B<DEBUG> instance variable which causes the raw output of
Crypt::PGP's interaction with the PGP binary to display.

=back

=head1 OBJECT METHODS

=over 2

=item B<sign (@message)>

Signs B<@message> with the secret key specified with B<secretkey ()>
and returns the result as an array of lines.

=item B<verify (@message)>

Verifies or decrypts the message in B<@message> and returns the
decrypted message. If the message was signed it returns (in this
order) the status of the signature, the signer's username, the signing
key ID, the time the signature was made, the time the signing key was
created, the signing key size, and a boolean value indicating whether
the signing key is trusted or not. Returns B<undef> if the signature
could not be verified.

=item B<dverify ([@message], [@signature])>

Verifies the detactched signature B<@signature> on B<@message> and
returns (in this order) the signer's username, the signing key ID, the
time the signature was made, the time the signing key was created, the
signing key size, and a boolean value indicating whether the signing
key is trusted or not, along with an array containing the plaintext
message. Returns B<undef> if the signature could not be verified.

=item B<msginfo (@ciphertext)>

Returns a list of the recipient key IDs that B<@ciphertext> is
encrypted to.

=item B<encrypt ([$keyid1, $keyid2...], @plaintext)>

Encrypts B<@plaintext> with the public keys of the recipients in the
arrayref passed as the first argument and returns the result.
B<undef> if there was an error while processing. Returns ciphertext if
the message could be encrypted to at least one of the recipients.

=item B<addkey ($key)>

Adds the keys given in B<$key> to the user's key ring and returns a
list of Crypt::PGP::Key objects corresponding to the keys that were
added.

=item B<delkey ($keyid)>

Deletes the key with B<$keyid> from the user's key ring.

=item B<disablekey ($keyid)>

Disables the key with B<$keyid>.

=item B<enablekey ($keyid)>

Enables the key with B<$keyid>.

=item B<keypass ($keyid, $oldpass, $newpass)>

Change the passphrase for a key. Returns true if the passphrase change
succeeded, false if not.

=item B<keylist ($ringdir)>

Returns an array of Crypt::PGP5::Key objects corresponding to the
user's keyfiles.

=item B<parsekeys (@keylist)>

Parses a raw PGP formatted key listing and returns a list of
Crypt::PGP5::Key objects.

=item B<extractkey ($userid, $keyring)>

Extracts the key for B<$userid> from B<$keyring> and returns the
result. The B<$keyring> argument is optional and defaults to the
public keyring set with B<pubring ()>.

=item B<keygen ($name, $email, $keytype, $keysize, $expire, $ringdir)>

Creates a new keypair with the parameters specified. B<$keytype> may
be one of 'RSA' or 'DSS'. B<$keysize> can be any of 768, 1024, 2048,
3072 or 4096 for DSS keys, and 768, 1024 or 2048 for RSA type
keys. Returns undef if there was an error, otherwise returns the Key
ID of the new key.

=head1 BUGS

Error checking needs work. Some keyring functions are missing. May not
work with versions of PGP other than PGPfreeware 5.0i. The method call
interface is subject to change in future versions.

=head1 AUTHOR

Crypt::PGP5 is Copyright (c) 1999-2000 Ashish Gulhati. All Rights
Reserved.

=head1 ACKNOWLEDGEMENTS

Thanks to my wife, Barkha, for support and inspiration; to Raj Mathur,
my Unix mentor; to Rex Rogers at Laissez Faire City (www.lfcity.com)
for putting together a great environment to hack on freedom
technologies; and of-course, to Phil Zimmerman, Larry Wall, Richard
Stallman, and Linus Torvalds.

=head1 LICENSE

You may use, modify and redistribute this module under the same terms
as Perl itself. It would be nice if you would mail your patches to me
at hash@netropolis.org and I would love to hear about projects that
make use of this module.

=head1 DISCLAIMER

This is free software. If it breaks, you own both parts.

=cut

'True Value';
