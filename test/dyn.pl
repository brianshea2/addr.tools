#!/usr/bin/perl

use strict;
use warnings;
use Digest::SHA qw(sha224_hex);
use URI::Escape;

sub curl        { print '.'; sleep 1; my $s = shift; `curl -s 'https://dyn.addr.tools/$s' @_` // '' }
sub dig         { `dig \@127.0.0.1 +short @_` // '' }
sub domain      { sha224_hex($_[0]) . '.dyn.addr.tools.' }
sub secret      { 'a=1&b=2; !@#$%^&*()/+' . $_[0] }
sub withNewline { "$_[0]\n" }
sub expect      { $_[0] eq $_[1] or warn "\nFAILED: line " . (caller)[2] . "; got: $_[0]; expected: $_[1]\n" }

# /?secret=<secret> GET
my $q = '?secret=' . uri_escape(secret(1));
expect( curl($q),                                               withNewline(domain(secret(1)))      );
expect( dig(domain(secret(1))),                                 ''                                  );
expect( curl("$q&ip=192.0.2.101"),                              withNewline('OK')                   );
expect( dig(domain(secret(1))),                                 withNewline('192.0.2.101')          );
expect( curl($q, '-X', 'DELETE'),                               ''                                  );
expect( dig(domain(secret(1))),                                 ''                                  );

# /?secret=<secret> POST
$q = '?secret=' . uri_escape(secret(2));
expect( curl($q),                                               withNewline(domain(secret(2)))      );
expect( dig(domain(secret(2))),                                 ''                                  );
expect( curl($q, '-d', '192.0.2.101'),                          withNewline('OK')                   );
expect( dig(domain(secret(2))),                                 withNewline('192.0.2.101')          );
expect( curl($q, '-X', 'DELETE'),                               ''                                  );
expect( dig(domain(secret(2))),                                 ''                                  );

# POST only
my $d = "--data-urlencode 'secret=" . secret(3) . "'";
expect( curl('', $d),                                           withNewline(domain(secret(3)))      );
expect( dig(domain(secret(3))),                                 ''                                  );
expect( curl('', $d, '-d', 'ip=192.0.2.101'),                   withNewline('OK')                   );
expect( dig(domain(secret(3))),                                 withNewline('192.0.2.101')          );
expect( curl('', $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret(3))),                                 ''                                  );

# PUT only
$d = "--data-urlencode 'secret=" . secret(4) . "'";
expect( curl('', $d, '-X', 'PUT'),                              withNewline(domain(secret(4)))      );
expect( dig(domain(secret(4))),                                 ''                                  );
expect( curl('', $d, '-X', 'PUT', '-d', 'ip=192.0.2.101'),      withNewline('OK')                   );
expect( dig(domain(secret(4))),                                 withNewline('192.0.2.101')          );
expect( curl('', $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret(4))),                                 ''                                  );

# POST with same GET
$q = '?secret=' . uri_escape(secret(5));
$d = "--data-urlencode 'secret=" . secret(5) . "'";
expect( curl($q, $d),                                           withNewline(domain(secret(5)))      );
expect( dig(domain(secret(5))),                                 ''                                  );
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.101'),  withNewline('OK')                   );
expect( dig(domain(secret(5))),                                 withNewline('192.0.2.101')          );
expect( curl($q, $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret(5))),                                 ''                                  );

# POST with different GET secret
$q = '?secret=' . uri_escape(secret(6));
$d = "--data-urlencode 'secret=" . secret(7) . "'";
expect( curl($q, $d),                                           withNewline('multiple values found for "secret"') );
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.101'),  withNewline('multiple values found for "secret"') );
expect( curl($q, $d, '-X', 'DELETE'),                           withNewline('multiple values found for "secret"') );

# POST with different GET ip
$q = '?secret=' . uri_escape(secret(8));
$d = "--data-urlencode 'secret=" . secret(8) . "'";
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.202'),  withNewline('multiple values found for "ip"') );

# invalid IP
$q = '?secret=' . uri_escape(secret(9));
$d = "--data-urlencode 'secret=" . secret(9) . "'";
expect( curl("$q&ip=192.0.2.abc"),                              withNewline('invalid value for "ip"')   );
expect( curl($q, '-d', 'ip=192.0.2.abc'),                       withNewline('invalid value for "ip"')   );
expect( curl('', $d, '-d', 'ip=192.0.2.abc'),                   withNewline('invalid value for "ip"')   );

# empty
expect( curl('', '-X', 'POST'),                                 withNewline('must specify "secret"')    );
expect( curl('', '-X', 'PUT'),                                  withNewline('must specify "secret"')    );

print "\nDONE\n";
