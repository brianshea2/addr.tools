#!/usr/bin/perl

use strict;
use warnings;
use Digest::SHA qw(sha224_hex);
use URI::Escape;

sub curl        { print '.'; sleep 1; my $s = shift; `curl -s 'https://challenges.addr.tools/$s' @_` // '' }
sub dig         { `dig \@127.0.0.1 +short txt @_` // '' }
sub domain      { sha224_hex($_[0]) . '.challenges.addr.tools.' }
sub secret      { 'test0-9A-Za-z=_-' . $_[0] }
sub secret2     { 'a=1&b=2; !@#$%^&*()/+' . $_[0] }
sub withNewline { "$_[0]\n" }
sub expect      { $_[0] eq $_[1] or warn "\nFAILED: line " . (caller)[2] . "; got: $_[0]; expected: $_[1]\n" }

# /<secret> GET
expect( curl(secret(1)),                                        withNewline(domain(secret(1)))      );
expect( dig(domain(secret(1))),                                 ''                                  );
expect( curl(secret(1) . '?txt=123ABCabc_-'),                   withNewline('OK')                   );
expect( dig(domain(secret(1))),                                 withNewline('"123ABCabc_-"')        );
expect( curl(secret(1) . '?txt=123ABCabc_-', '-X', 'DELETE'),   ''                                  );
expect( dig(domain(secret(1))),                                 ''                                  );

# /<secret> POST
expect( curl(secret(2)),                                        withNewline(domain(secret(2)))      );
expect( dig(domain(secret(2))),                                 ''                                  );
expect( curl(secret(2), '-d', '123ABCabc_-'),                   withNewline('OK')                   );
expect( dig(domain(secret(2))),                                 withNewline('"123ABCabc_-"')        );
expect( curl(secret(2), '-d', '123ABCabc_-', '-X', 'DELETE'),   ''                                  );
expect( dig(domain(secret(2))),                                 ''                                  );

# /?secret=<secret> GET
my $q = '?secret=' . uri_escape(secret2(3));
expect( curl($q),                                               withNewline(domain(secret2(3)))     );
expect( dig(domain(secret2(3))),                                ''                                  );
expect( curl("$q&txt=123ABCabc_-"),                             withNewline('OK')                   );
expect( dig(domain(secret2(3))),                                withNewline('"123ABCabc_-"')        );
expect( curl("$q&txt=123ABCabc_-", '-X', 'DELETE'),             ''                                  );
expect( dig(domain(secret2(3))),                                ''                                  );

# /?secret=<secret> POST
$q = '?secret=' . uri_escape(secret2(4));
expect( curl($q),                                               withNewline(domain(secret2(4)))     );
expect( dig(domain(secret2(4))),                                ''                                  );
expect( curl($q, '-d', '123ABCabc_-'),                          withNewline('OK')                   );
expect( dig(domain(secret2(4))),                                withNewline('"123ABCabc_-"')        );
expect( curl($q, '-d', '123ABCabc_-', '-X', 'DELETE'),          ''                                  );
expect( dig(domain(secret2(4))),                                ''                                  );

# POST only
my $d = "--data-urlencode 'secret=" . secret2(5) . "'";
expect( curl('', $d),                                           withNewline(domain(secret2(5)))     );
expect( dig(domain(secret2(5))),                                ''                                  );
expect( curl('', $d, '-d', 'txt=123ABCabc_-'),                  withNewline('OK')                   );
expect( dig(domain(secret2(5))),                                withNewline('"123ABCabc_-"')        );
expect( curl('', $d, '-d', 'txt=123ABCabc_-', '-X', 'DELETE'),  ''                                  );
expect( dig(domain(secret2(5))),                                ''                                  );

# POST with same GET
$q = '?secret=' . uri_escape(secret2(6));
$d = "--data-urlencode 'secret=" . secret2(6) . "'";
expect( curl($q, $d),                                                               withNewline(domain(secret2(6))) );
expect( dig(domain(secret2(6))),                                                    ''                              );
expect( curl("$q&txt=123ABCabc_-", $d, '-d', 'txt=123ABCabc_-'),                    withNewline('OK')               );
expect( dig(domain(secret2(6))),                                                    withNewline('"123ABCabc_-"')    );
expect( curl("$q&txt=123ABCabc_-", $d, '-d', 'txt=123ABCabc_-', '-X', 'DELETE'),    ''                              );
expect( dig(domain(secret2(6))),                                                    ''                              );

# POST with different GET secret
$q = '?secret=' . uri_escape(secret2(7));
$d = "--data-urlencode 'secret=" . secret2(8) . "'";
expect( curl($q, $d),                                                               withNewline('multiple values found for "secret"') );
expect( curl("$q&txt=123ABCabc_-", $d, '-d', 'txt=123ABCabc_-'),                    withNewline('multiple values found for "secret"') );
expect( curl("$q&txt=123ABCabc_-", $d, '-d', 'txt=123ABCabc_-', '-X', 'DELETE'),    withNewline('multiple values found for "secret"') );

# POST with different GET txt
$q = '?secret=' . uri_escape(secret2(9));
$d = "--data-urlencode 'secret=" . secret2(9) . "'";
expect( curl("$q&txt=123ABCabc_-", $d, '-d', 'txt=somethingelse'),                  withNewline('multiple values found for "txt"') );

# invalid txt
$q = '?secret=' . uri_escape(secret2(10));
$d = "--data-urlencode 'secret=" . secret2(10) . "'";
expect( curl("$q&txt=invalid.value"),                           withNewline('invalid value for "txt"')  );
expect( curl($q, '-d', 'txt=invalid.value'),                    withNewline('invalid value for "txt"')  );
expect( curl('', $d, '-d', 'txt=invalid.value'),                withNewline('invalid value for "txt"')  );
$d = '-d secret=testmakesurethissecretisnotusedastxtvalue';
expect( curl('', $d),                                           withNewline(domain('testmakesurethissecretisnotusedastxtvalue')) );
expect( curl('', $d, '-X', 'DELETE'),                           withNewline('must specify "txt"')       );

# empty
expect( curl('', '-X', 'POST'),                                 withNewline('must specify "secret"')    );

print "\nDONE\n";
