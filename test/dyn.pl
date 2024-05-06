#!/usr/bin/perl

use strict;
use warnings;
use Digest::SHA qw(sha224_hex);
use URI::Escape;

sub curl        { print '.'; sleep 1; my $s = shift; `curl -s 'https://dyn.addr.tools/$s' @_` // '' }
sub dig         { `dig \@127.0.0.1 +short @_` // '' }
sub domain      { sha224_hex($_[0]) . '.dyn.addr.tools.' }
sub secret      { 'test0-9A-Za-z=_-' . $_[0] }
sub secret2     { 'a=1&b=2; !@#$%^&*()/+' . $_[0] }
sub withNewline { "$_[0]\n" }
sub expect      { $_[0] eq $_[1] or warn "\nFAILED: line " . (caller)[2] . "; got: $_[0]; expected: $_[1]\n" }

# /<secret> GET
expect( curl(secret(1)),                                        withNewline(domain(secret(1)))      );
expect( dig(domain(secret(1))),                                 ''                                  );
expect( curl(secret(1) . '?ip=192.0.2.101'),                    withNewline('OK')                   );
expect( dig(domain(secret(1))),                                 withNewline('192.0.2.101')          );
expect( curl(secret(1), '-X', 'DELETE'),                        ''                                  );
expect( dig(domain(secret(1))),                                 ''                                  );

# /<secret> POST
expect( curl(secret(2)),                                        withNewline(domain(secret(2)))      );
expect( dig(domain(secret(2))),                                 ''                                  );
expect( curl(secret(2), '-d', '192.0.2.101'),                   withNewline('OK')                   );
expect( dig(domain(secret(2))),                                 withNewline('192.0.2.101')          );
expect( curl(secret(2), '-X', 'DELETE'),                        ''                                  );
expect( dig(domain(secret(2))),                                 ''                                  );

# /<secret> PUT
expect( curl(secret(3)),                                        withNewline(domain(secret(3)))      );
expect( dig(domain(secret(3))),                                 ''                                  );
expect( curl(secret(3), '-d', '192.0.2.101', '-X', 'PUT'),      withNewline('OK')                   );
expect( dig(domain(secret(3))),                                 withNewline('192.0.2.101')          );
expect( curl(secret(3), '-X', 'DELETE'),                        ''                                  );
expect( dig(domain(secret(3))),                                 ''                                  );

# /?secret=<secret> GET
my $q = '?secret=' . uri_escape(secret2(4));
expect( curl($q),                                               withNewline(domain(secret2(4)))     );
expect( dig(domain(secret2(4))),                                ''                                  );
expect( curl("$q&ip=192.0.2.101"),                              withNewline('OK')                   );
expect( dig(domain(secret2(4))),                                withNewline('192.0.2.101')          );
expect( curl($q, '-X', 'DELETE'),                               ''                                  );
expect( dig(domain(secret2(4))),                                ''                                  );

# /?secret=<secret> POST
$q = '?secret=' . uri_escape(secret2(5));
expect( curl($q),                                               withNewline(domain(secret2(5)))     );
expect( dig(domain(secret2(5))),                                ''                                  );
expect( curl($q, '-d', '192.0.2.101'),                          withNewline('OK')                   );
expect( dig(domain(secret2(5))),                                withNewline('192.0.2.101')          );
expect( curl($q, '-X', 'DELETE'),                               ''                                  );
expect( dig(domain(secret2(5))),                                ''                                  );

# POST only
my $d = "--data-urlencode 'secret=" . secret2(6) . "'";
expect( curl('', $d),                                           withNewline(domain(secret2(6)))     );
expect( dig(domain(secret2(6))),                                ''                                  );
expect( curl('', $d, '-d', 'ip=192.0.2.101'),                   withNewline('OK')                   );
expect( dig(domain(secret2(6))),                                withNewline('192.0.2.101')          );
expect( curl('', $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret2(6))),                                ''                                  );

# PUT only
$d = "--data-urlencode 'secret=" . secret2(7) . "'";
expect( curl('', $d, '-X', 'PUT'),                              withNewline(domain(secret2(7)))     );
expect( dig(domain(secret2(7))),                                ''                                  );
expect( curl('', $d, '-X', 'PUT', '-d', 'ip=192.0.2.101'),      withNewline('OK')                   );
expect( dig(domain(secret2(7))),                                withNewline('192.0.2.101')          );
expect( curl('', $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret2(7))),                                ''                                  );

# POST with same GET
$q = '?secret=' . uri_escape(secret2(8));
$d = "--data-urlencode 'secret=" . secret2(8) . "'";
expect( curl($q, $d),                                           withNewline(domain(secret2(8)))     );
expect( dig(domain(secret2(8))),                                ''                                  );
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.101'),  withNewline('OK')                   );
expect( dig(domain(secret2(8))),                                withNewline('192.0.2.101')          );
expect( curl($q, $d, '-X', 'DELETE'),                           ''                                  );
expect( dig(domain(secret2(8))),                                ''                                  );

# POST with different GET secret
$q = '?secret=' . uri_escape(secret2(9));
$d = "--data-urlencode 'secret=" . secret2(10) . "'";
expect( curl($q, $d),                                           withNewline('multiple values found for "secret"') );
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.101'),  withNewline('multiple values found for "secret"') );
expect( curl($q, $d, '-X', 'DELETE'),                           withNewline('multiple values found for "secret"') );

# POST with different GET ip
$q = '?secret=' . uri_escape(secret2(11));
$d = "--data-urlencode 'secret=" . secret2(11) . "'";
expect( curl("$q&ip=192.0.2.101", $d, '-d', 'ip=192.0.2.202'),  withNewline('multiple values found for "ip"') );

# invalid IP
$q = '?secret=' . uri_escape(secret2(12));
$d = "--data-urlencode 'secret=" . secret2(12) . "'";
expect( curl("$q&ip=192.0.2.abc"),                              withNewline('invalid value for "ip"')   );
expect( curl($q, '-d', 'ip=192.0.2.abc'),                       withNewline('invalid value for "ip"')   );
expect( curl('', $d, '-d', 'ip=192.0.2.abc'),                   withNewline('invalid value for "ip"')   );

# empty
expect( curl('', '-X', 'POST'),                                 withNewline('must specify "secret"')    );
expect( curl('', '-X', 'PUT'),                                  withNewline('must specify "secret"')    );

print "\nDONE\n";
