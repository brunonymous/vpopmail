version 2023.08.21

vpopmail-defaultdelivery patch for vpopmail-5.4.33 by Roberto Puzzanghera
More info here https://notes.sagredo.eu/en/qmail-notes-185/installing-and-configuring-vpopmail-81.html

==============================================================================================================

Normally vpopmail copies its delivery agent vdelivermail into the .qmail-default file of newly created
domains. Changing the delivery agent vdelivermail in the .qmail-default file will get your system to gain
the sieve rules functionality by dovecot, for instance. But in this case the valiases stored in MySQL will
no longer be recognized.

Having the vpopmail's vdelivermail into the .qmail-default and the dovecot (or whatelse) delivery agent in the
user's .qmail will preserve the virtual aliases, which will be handled by vpopmail in the .qmail-default file,
but will get your favorite LDA to be called from within the mailbox .qmail file.

In addition, having the aliases on MySQL is a benefit as you can build plugins for RoundCube (or your favorite
webmail) to handle them. And, last but not least, letting vpopmail to handle your aliases instead of a sieve rule
will make qmail to rewrite the sender address (SRS) and preserve the SPF validity of the original sender.

This patch will get the qmail/vpopmail system to achieve this. It makes vpopmail to copy your favourite 
delivery agent, stored in QMAILDIR/control/defauldelivery in the mailbox's .qmail.

In addition, this patch makes vdelivermail to be installed in .qmail-default with the "delete" option instead of
"bounce-no-mailbox", which is not reasonable anymore.

The vmakedotqmail program will help you in the transition. It will populate/restore all your .qmail files for
you. Have a look to it:

vmakedotqmail -h for more info.

== Settings

An autoreconf is needed as I modified the original configure.in and Makefile.am files.

Configure as follows:

autoreconf -f -i
./configure --enable-defaultdelivery (default OFF)

== Looking for the old patch?

If you like to have the old vpopmail-defaultdelivery patch of mine, which installs the defaultdelivery in
.qmail-default, look here:
https://notes.sagredo.eu/files/qmail/patches/vpopmail/vpopmail-5.4.33-defaultdelivery-domains.patch
