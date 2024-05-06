#!/usr/bin/perl

use strict;
use warnings;

sub dig         { `dig \@127.0.0.1 +short @_` // '' }
sub domain      { "$_[0].ip.addr.tools." }
sub withNewline { "$_[0]\n" }
sub expect      { $_[0] eq $_[1] or warn "\nFAILED: line " . (caller)[2] . "; got: $_[0]; expected: $_[1]\n" }

expect( dig(domain('192-0-2-101')),                             withNewline('192.0.2.101')          );
expect( dig(domain('abc.def.192-0-2-101')),                     withNewline('192.0.2.101')          );
expect( dig(domain('192.0.2.101')),                             withNewline('192.0.2.101')          );
expect( dig(domain('abc.def.192.0.2.101')),                     withNewline('192.0.2.101')          );
expect( dig(domain('2001-db8--c0-ffee'), 'aaaa'),               withNewline('2001:db8::c0:ffee')    );
expect( dig(domain('abc.def.2001-db8--c0-ffee'), 'aaaa'),       withNewline('2001:db8::c0:ffee')    );

`/usr/bin/echo -e "update add _acme-challenge.172-31-255-101.ip.addr.tools 1 txt testtest1\nsend\nquit" | nsupdate`;
expect( dig(domain('_acme-challenge.172-31-255-101'), 'txt'),           withNewline('"testtest1"')  );

`/usr/bin/echo -e "update add _acme-challenge.abc.def.172-31-255-101.ip.addr.tools 1 txt testtest2\nsend\nquit" | nsupdate`;
expect( dig(domain('_acme-challenge.abc.def.172-31-255-101'), 'txt'),   withNewline('"testtest2"')  );

`/usr/bin/echo -e "update add _acme-challenge.fd01-db8--c0-ffee.ip.addr.tools 1 txt testtest3\nsend\nquit" | nsupdate`;
expect( dig(domain('_acme-challenge.fd01-db8--c0-ffee'), 'txt'),        withNewline('"testtest3"')  );

`/usr/bin/echo -e "update add _acme-challenge.abc.fd01-db8--c0-ffee.ip.addr.tools 1 txt testtest4\nsend\nquit" | nsupdate`;
expect( dig(domain('_acme-challenge.abc.fd01-db8--c0-ffee'), 'txt'),    withNewline('"testtest4"')  );

print "\nDONE\n";
