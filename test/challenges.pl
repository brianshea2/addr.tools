#!/usr/bin/perl

use strict;
use warnings;
use Digest::SHA qw(sha224_hex sha256);
use MIME::Base64 qw(encode_base64url);
use URI::Escape;

sub curl        { print '.'; sleep 1; my $s = shift; `curl -s 'https://challenges.addr.tools/$s' @_` // '' }
sub dig         { `dig \@127.0.0.1 +short txt @_` // '' }
sub domain      { sha224_hex($_[0]) . '.challenges.addr.tools.' }
sub secret      { 'a=1&b=2; !@#$%^&*()/+' . $_[0] }
sub txt         { encode_base64url(sha256($_[0])) }
sub withNewline { "$_[0]\n" }
sub expect      { $_[0] eq $_[1] or warn "\nFAILED: line " . (caller)[2] . "; got: $_[0]; expected: $_[1]\n" }

# /?secret=<secret> GET
my $q = '?secret=' . uri_escape(secret(1));
my $txt = txt(1);
expect( curl($q),                                               withNewline(domain(secret(1)))      );
expect( dig(domain(secret(1))),                                 ''                                  );
expect( curl("$q&txt=$txt"),                                    withNewline('OK')                   );
expect( dig(domain(secret(1))),                                 withNewline("\"$txt\"")             );
expect( curl("$q&txt=$txt", '-X', 'DELETE'),                    ''                                  );
expect( dig(domain(secret(1))),                                 ''                                  );

# /?secret=<secret> POST
$q = '?secret=' . uri_escape(secret(2));
$txt = txt(2);
expect( curl($q),                                               withNewline(domain(secret(2)))      );
expect( dig(domain(secret(2))),                                 ''                                  );
expect( curl($q, '-d', $txt),                                   withNewline('OK')                   );
expect( dig(domain(secret(2))),                                 withNewline("\"$txt\"")             );
expect( curl($q, '-d', $txt, '-X', 'DELETE'),                   ''                                  );
expect( dig(domain(secret(2))),                                 ''                                  );

# POST only
my $d = "--data-urlencode 'secret=" . secret(3) . "'";
$txt = txt(3);
expect( curl('', $d),                                           withNewline(domain(secret(3)))      );
expect( dig(domain(secret(3))),                                 ''                                  );
expect( curl('', $d, '-d', "txt=$txt"),                         withNewline('OK')                   );
expect( dig(domain(secret(3))),                                 withNewline("\"$txt\"")             );
expect( curl('', $d, '-d', "txt=$txt", '-X', 'DELETE'),         ''                                  );
expect( dig(domain(secret(3))),                                 ''                                  );

# POST with same GET
$q = '?secret=' . uri_escape(secret(4));
$d = "--data-urlencode 'secret=" . secret(4) . "'";
$txt = txt(4);
expect( curl($q, $d),                                                               withNewline(domain(secret(4)))  );
expect( dig(domain(secret(4))),                                                     ''                              );
expect( curl("$q&txt=$txt", $d, '-d', "txt=$txt"),                                  withNewline('OK')               );
expect( dig(domain(secret(4))),                                                     withNewline("\"$txt\"")         );
expect( curl("$q&txt=$txt", $d, '-d', "txt=$txt", '-X', 'DELETE'),                  ''                              );
expect( dig(domain(secret(4))),                                                     ''                              );

# POST with different GET secret
$q = '?secret=' . uri_escape(secret(5));
$d = "--data-urlencode 'secret=" . secret(6) . "'";
$txt = txt(5);
expect( curl($q, $d),                                                               withNewline('multiple values found for "secret"') );
expect( curl("$q&txt=$txt", $d, '-d', "txt=$txt"),                                  withNewline('multiple values found for "secret"') );
expect( curl("$q&txt=$txt", $d, '-d', "txt=$txt", '-X', 'DELETE'),                  withNewline('multiple values found for "secret"') );

# POST with different GET txt
$q = '?secret=' . uri_escape(secret(7));
$d = "--data-urlencode 'secret=" . secret(7) . "'";
$txt = txt(6);
my $txt2 = txt(7);
expect( curl("$q&txt=$txt", $d, '-d', "txt=$txt2"),                                 withNewline('multiple values found for "txt"') );

# invalid txt
$q = '?secret=' . uri_escape(secret(8));
$d = "--data-urlencode 'secret=" . secret(8) . "'";
expect( curl("$q&txt=invalid"),                                 withNewline('invalid value for "txt"')  );
expect( curl($q, '-d', 'txt=invalid'),                          withNewline('invalid value for "txt"')  );
expect( curl('', $d, '-d', 'txt=invalid'),                      withNewline('invalid value for "txt"')  );

# empty
$d = "--data-urlencode 'secret=" . secret(9) . "'";
expect( curl('', $d, '-X', 'DELETE'),                           withNewline('must specify "txt"')       );
expect( curl('', '-X', 'POST'),                                 withNewline('must specify "secret"')    );

print "\nDONE\n";
