#!/usr/bin/perl

# USE AT YOUR OWN RISK!!! Sendmail2Vpopmail.pl v0.0.4  Date:21.07.2003
#
# v0.0.2	* Fixed the bug in chmod/chown not working and default forwards
#                 limit not assigned.
# v0.0.3	* Fixed the bug of creating aliases/forwards with . inside
# v0.0.4	* Fixed the bug of creating aliases/forwards with capital letters
#
# This script "should" convert sendmail users including users from virtusertable
# files to vpopmail. It only works for vpopmail installations which DOES NOT
# utilize LARGE_SITE. Although it would be trivial to include large site support.
# Script also can read the system quota limits for the directory where the mail
# of users is located and transfer it to vpopmail system
#
# FEATURES
#
# * Supports converting system quotas
# * Supports setting a minimum quota for users with or without quota
# * Supports setting a default quota if system quota is not used
#   or if a user doesnt have system quota
# * Supports virtusertable file
# * Supports setting QmailAdmin and vQadmin limits
# * Supports system traditional system mail spool directory or
#   if the mail is stored in user directory.
# * Supports processing of password file for a default domain name
#   for the users which do not exist in virtusertable
# * Suports creating aliases or forwards from virtusertable file for
#   users whouse virtual username is not same with system username
# * Supports putting all users to default domain without processing
#   virtusertable file
# * Supports creating duplicate accounts in default domain for the 
#   users already processed in virtusertable file
# * Supports processing of alias file
# * Works with DES or MD5 passwords on FreeBSD
#
# TODO
#
# * Script could log its actions...
# * LARGE_SITE support...
# * Script could support aliases file better...
# * Cleaning variables!
#
# BUGS
#
# * There is no simple way to know (at least for me) the domain's directory
#   path in vpopmail system. This script is just assuming that since postmaster
#   is the first account to be created, it must be in the domain's first
#   level. Then extracts one directory and finds the domain directory.
# * If a username is aliased to aliased alias then this wont work.
#   If somebody knows how to fix this then please contact me!
# * Too many variables used...
# * If a username is under multiple virtual domains, then it wont be
#   created for the other domains. (unless duplicate is selected?)
#
# NOTES
#
# * Be sure that the quotas are enabled if you mount your users directory
#   with NFS or similar. I did this mistake and no quotas were processed!
# * Be sure that you disable debugging sleep times to 0 otherwise it will
#   take long long time to process all your users.
# 
# For any comments or if you add new features, please contact with me.
# Evren Yurtesen <yurtesen@ispro.net.tr>
#
# I have tested this script on a FreeBSD system with about 10000 users with
# quotas and the mail files stored on user directories. The rest is untested!
# So if you have any experiences please write!


#there is no doubt these modules MUST be installed in your system! :)
use DBI;
use Quota;

# debuglevel: increase the number for more and more messages
# currently only 0-10-20 levels exist
$DEBUG=0;
#waiting time after a debug message
$SLEEPTIME=1;

#system alias file
#if an empty file is given then it will be ignored
#(/dev/null would suffice perhaps)
#it is needed if you have been using alias file in
#conjunction with virtusertable file. For example
#if you have this in your virtusertable file
#abc@abc.com                    abc
#and in your alias file
#abc:   abc1,abc2,abc3
$ALIASFILE="/etc/aliases";
#$ALIASFILE="/dev/null";

#system virtusertable file
#if an empty file is given then all users in password file 
#will be added to defaultdomain (/dev/null would suffice)
$VIRTFILE="virtusertable";
#$VIRTFILE="/dev/null";

#do you want to create all users in password file, also in the
#default domain? even if they were previously created because
#they exist in virtusertable file? if set to 1 then duplicates
#will be created
$DUPLICATE=0;

#FreeBSD password file (might work for Linux shadow?)a
$PASSFILE="/etc/master.passwd";

#do you want to use system quota? if enabled then the script
#will find the hard limit of the user.
#the inode limit is not processed!
#to disable, set to 0
$SYSTEMQUOTA=1;

#default quota for all moved users (in bytes) or if SYSTEMQUOTA
#is set, then this effects the users who doesnt have quota if
#DEFAULTQUOTA is set to 0 then the users wont have quota if
#SYSTEMQUOTA is also disabled. If SYSTEMQUOTA is enabled then the
#users who doesnt have system quotas will not have quota
$DEFAULTQUOTA="10000000S";

#well considering the hard drive technology is advancing quite fast,
#you might want to increase the minimum quota for your users.
#lets say if they have a quota of 6000kbyte then you can increase
#it to 10000kbyte if MINQUOTA is set to 10000.
#if the user has 12000kbyte then it wont effect anything
#if set to 0 then it wont have effect (obviously)
#if you are not checking SYSTEMQUOTA then MINQUOTA does not have
#any effect
$MINQUOTA="10000";

#minimum and maximum userid's while processing the password file
#this is required so that you wont process root account etc.
#accidentally and make an email address with root password!
#it wouldnt be nice :p
$MINUID=100;
$MAXUID=60000;

#VPOPMAIL USER/GROUP
$VPOPMAILUSER="vpopmail";
$VPOPMAILGROUP="vchkpw";

#default domain limits for qmailadmin etc. will have this quotas etc.
#a value of 0 disables that functionality.
$DEFAULTDOMUSERLIMIT="20";
$DEFAULTALIASLIMIT="100";
$DEFAULTFORWARDSLIMIT="5";
$DEFAULTAUTORESPONDERLIMIT="0";
$DEFAULTMAILLISTLIMIT="0";
$DEFAULTDOMQUOTA="10000000S";

#are you using spool directory 0 or user homedirs 1 to store mail?
$SPOOL=0;
#system mail spool directory (do not set it if user inboxes are in their homedirs)!
#$SYSDIR="/var/spool/mail";
#inbox file (set it to location of inbox of user inside his directory if user inboxes
#are in their homedirs);
#$INBOX=$sysuname; #sets the user INBOX name to his username
$INBOX="mail/INBOX";

#the default vpopmail directory
#the domains directory and bin directory must be inside!
$VPOPMAILHOMEDIR="/usr/local/vpopmail";

#default domain for users which are not in virtusertable
#if set to "none" only users in virtusertable is processed.
#be aware that it is not possible to process a single domain
#excluding the users in virtusertable file without processing
#the virtusertable file
$DEFAULTDOMAIN="mydomain.net";

#default postmaster password for all domains
$POSTMASTERPASSWORD="mypassword";

#sql settings
$SQL_DATABASE="vpopmail";
$SQL_SERVER="localhost";
$SQL_USERNAME="vpopmail";
$SQL_PASSWORD="mypassword";

#configuration ends here-----------------------------------------------


#open virtusertable file
open(MYVIRTFILE,"< $VIRTFILE") or die "I could not open $VIRTFILE exiting ....";

#open password file and put into an array, since we will use this MANY times
open(MYPASSFILEH,"< $PASSFILE") or die "I could not open $PASSFILE exiting ....";
@MYPASSFILE=<MYPASSFILEH>;
close (MYPASSFILE);

#open alias file and put into an array, since we will use this MANY times   
open(MYALIASFILEH,"< $ALIASFILE") or die "I could not open $ALIASFILE exiting ....";
@MYALIASFILE=<MYALIASFILEH>;
close (MYALIASFILEH);

#connect to database...
$dbh = DBI->connect("DBI:mysql:$SQL_DATABASE:$SQL_SERVER","$SQL_USERNAME","$SQL_PASSWORD")
    or die "I could not connect $SQL_DATABASE at $SQL_SERVER with $SQL_USERNAME identified by $SQL_PASSWORD";

#reset some variables, just to be sure :)
$countalias=0;
$countdefaultdomain=0;
$countforward=0;
$countuser=0;
$domaindone=0;
$userdone=0;
$samevirtsys=0;


#Go through the virtusertable file
while( $line=<MYVIRTFILE> ) {
  chomp($line);
  #just skip the lines which doesnt have any meaning for us...
  if ($line =~ /@/ && ! ($line =~ /^#/ ) ) {
    #parse the virtusertable and find virtusername, virtuserdomain, systemusername
    @values=split(/[\ \t]+/,$line);
    $values[0] =~ s/^\s+|\s+$//g;
    $values[1] =~ s/^\s+|\s+$//g;
    @values1=split(/@/,$values[0]);
    #put virtuser values to variables
    $virtuname=$values1[0];
    $domain=$values1[1];
    $sysuname=$values[1];
    #detect if we already processed some stuff in a previous run...
    foreach $elem (@donedom) {
      if($elem eq $domain) {
        $domaindone=1;
      }
    }
    foreach $elem (@doneuser) {
      if($elem eq $sysuname) {
        $userdone=1;
      }
    }
    #do not do anything for stuff we wont need
    if ( $sysuname =~ /error:/ || $virtuname eq "") {
      if($DEBUG >= 20) {
        print("Not searching default user password for domain $domain. Simply needless... \n");
        sleep($SLEEPTIME);
      }
    } else {
      &createvpopmailuser($sysuname);
      &processalias;
      &createaliasforward;
    }
  }
}

close (MYVIRTFILE);

#process the default domain
print("\n\nProcessing default domain $DEFAULTDOMAIN \n");
print("It might take a while. You can monitor your SQL \n");
print("database or vpopmail domains directory to see \n");
print("what is going on \n\n\n");

$domain=$DEFAULTDOMAIN;
&createvpopmailuser("PROCESS_WHOLE_PASSWORD_FILE");

print ("Setting user/group owners and access rights\n");
`chown -R $VPOPMAILUSER:$VPOPMAILGROUP $VPOPMAILHOMEDIR/domains`;
`chmod -R go-rwx $VPOPMAILHOMEDIR/domains`;

print ("Number of domains processed:\t\t\t\t",$#donedom + 1,"\n");
print ("Number of virtusers processed:\t\t\t\t",$#doneuser + 1,"\n");
print ("Number of system users processed:\t\t\t",$#doneuser + 1 + $countvpopuser,"\n");
if ($DUPLICATE ne 0) {
  print ("Number of default domain users processed:\t\t",@doneuser1 + 1,"\n");
} else {
  print ("Number of default domain users processed:\t\t",$countdefaultdomain,"\n");
}
print ("Number of aliases processed:\t\t\t\t", $countalias,"\n");
print ("Number of aliases from alias file processed:\t\t",@donealias + 1,"\n");
print ("Number of forwards processed:\t\t\t\t",$countforward,"\n");
print ("Number of forwards from alias file processed:\t\t",$countaliasforward,"\n");

$dbh->disconnect();

#processalias()
sub processalias { 
#now we could stop processing if the user is created already
#but god(root?) knows if alias is aliased to itself
  foreach $line2 (@MYALIASFILE) {
    @values3=split(/:/,$line2);
    if( ( ! ($line2 =~ /^#/) ) && $_[0] ne "PROCESS_WHOLE_ALIAS_FILE") {
      $aliasname=$values3[0];
      $aliasname=~ s/^\s+|\s+$//g;
      if ($sysuname eq $aliasname) {
        push(@donealias,$aliasname);
        @aliastgt=split(/,/,$values3[1]);
        foreach $line3 (@aliastgt) {
          $line3=~ s/^\s+|\s+$//g;
          if( $line3 =~ /@/) {
            $countaliasforward+=1;
            if($DEBUG >= 10) {
              print("Creating forward for user $virtuname\@$domain to $line3 \n");
            }
            $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='postmaster'  and pw_domain='$domain'");
            $sth->execute;
            while (my $ref = $sth->fetchrow_arrayref) {
              $mdir= $$ref[0];
            }
            $sth->finish;
            #fix the aliases with . inside to :
            $virtuname1=$virtuname;
            $virtuname1=~ s/(.+)\.(.+)/$1\:$2/g;
            $virtuname1=lc($virtuname);
            open(OUTFILE, ">$mdir/../.qmail-$virtuname1");
            print OUTFILE "&$line3";
            close (OUTFILE);  
          } else {
            if($DEBUG >= 20) {
              print("Creating $line3 which is aliased from the alias $sysuname in virtusertable \n");
              &createvpopmailuser($line3);
            }
          }
        }
      }
    }
  }  
}

#createaliasforward()
sub createaliasforward {
  #do not create an alias for the user we already created
  if ($virtuname ne $sysuname) {
    if ($sysuname =~ /error:/ ) {
      if($DEBUG >= 20) {
        print("We do not create aliases for error messages at $domain to $sysuname\n");
      }
    } else {
      if ($virtuname eq "") {
        if($DEBUG >= 20) {
          print("Changing default email address to catchall account for $domain $sysuname\@$domain\n");
        }
        $virtuname=default;
      }
      #figure out if this is a forward or alias
      if($sysuname =~ /@/) {
        $countforward+=1;
        if($DEBUG >= 10) {
          print("Creating forward for user $virtuname\@$domain to $sysuname \n");
        }
        $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='postmaster'  and pw_domain='$domain'");
        $sth->execute;
        while (my $ref = $sth->fetchrow_arrayref) {
          $mdir= $$ref[0];
        }
	$sth->finish;
        #fix the aliases with . inside to :
        $virtuname1=$virtuname;
        $virtuname1=~ s/(.+)\.(.+)/$1\:$2/g;
        $virtuname1=lc($virtuname);
        open(OUTFILE, ">$mdir/../.qmail-$virtuname1");
        print OUTFILE "&$sysuname";
        close (OUTFILE);
      } else {
        $countalias+=1;
        if($DEBUG >= 10) {
          print("Creating Alias for User $virtuname\@$domain to $sysuname\@$domain \n");
        }
        $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='postmaster'  and pw_domain='$domain'");
        $sth->execute;
        while (my $ref = $sth->fetchrow_arrayref) {
          $mdir= $$ref[0];
        }
	$sth->finish;
        #fix the aliases with . inside to :
        $virtuname1=$virtuname;
        $virtuname1=~ s/(.+)\.(.+)/$1\:$2/g;
        $virtuname1=lc($virtuname);
        open(OUTFILE, ">$mdir/../.qmail-$virtuname1");
        $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='$sysuname'  and pw_domain='$domain'");
        $sth->execute;
        while (my $ref = $sth->fetchrow_arrayref) {
          $mdir= $$ref[0];
        }
	$sth->finish;
        print OUTFILE "$mdir/Maildir/\n";
        close (OUTFILE);
      }
    }
  }
}

#createvpopmailuser($username)
sub createvpopmailuser {
$notalias=0;
  foreach $line1 (@MYPASSFILE) {
    $domaindone=0;
    $userdone=1;
    @values2=split(/:/,$line1);
    if( ( ! ($line1 =~ /^#/) ) && $_[0] eq "PROCESS_WHOLE_PASSWORD_FILE") {
      $sysuname=$values2[0];
      $syspass=$values2[1];
      $sysuid=$values2[2];
      if ($SPOOL eq 0) {
        $SYSDIR=$values2[8];
      }
      $userdone=0;
    }
    if( ( ! ($line1 =~ /^#/) ) && $_[0] eq $values2[0]) {
      $sysuname=$values2[0];
      $syspass=$values2[1];
      $sysuid=$values2[2];
      if ($SPOOL eq 0) {
        $SYSDIR=$values2[8];
      }
      $userdone=0;
    }
    if ( ($values2[2] < $MINUID || $values2[2] > $MAXUID) && $userdone eq 0) {
      if ($DEBUG >= 10 && $userdone eq 0) {
        print("Skipping creation of users UID less than $MINUID or more than $MAXUID\n");
        print("Please process virtual accounts pointing to system account $sysuname manually\n");
        sleep($SLEEPTIME);
      }
      $userdone=1;
    }
    #detect if we already processed some stuff...
    foreach $elem (@donedom) {
      if($elem eq $domain) {
        $domaindone=1;
      }
    }
    if($DUPLICATE eq 0) {
      #if the username has @ then its forward...
      foreach $elem (@doneuser) {
        if($elem eq $sysuname || $sysuname =~ /@/ ) {
          $userdone=1;
        }
      }
    } else {
      foreach $elem (@doneuser1) {
        if($elem eq $sysuname || $sysuname =~ /@/ ) {
          $userdone=1;
        }
      }
    }
    if ($DEBUG >= 20 && $userdone eq 0) {
      print("System Username:UID:Password:Home/Spool Directory: $sysuname:$sysuid:$syspass:$SYSDIR \n");
      sleep($SLEEPTIME);
    }
    #if we are creating a user for this domain first time.
    if ($domaindone ne 1) {
      print("Creating domain $domain and user(s)\n");
      `$VPOPMAILHOMEDIR/bin/vadddomain  $domain  $POSTMASTERPASSWORD`;
      $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='postmaster'  and pw_domain='$domain'");
      $sth->execute;
      while (my $ref = $sth->fetchrow_arrayref) {
        $mdir= $$ref[0];
      }
      $sth->finish;
      open(OUTFILE, ">$mdir/../.qmailadmin-limits");
      print OUTFILE "maxpopaccounts: $DEFAULTDOMUSERLIMIT\n";
      print OUTFILE "maxaliases: $DEFAULTALIASLIMIT\n";
      print OUTFILE "maxforwards: $DEFAULTFORWARDSLIMIT\n";
      print OUTFILE "maxautoresponders: $DEFAULTAUTORESPONDERLIMIT\n";
      print OUTFILE "maxmailinglists: $DEFAULTMAILLISTLIMIT\n";
      print OUTFILE "default_quota: $DEFAULTDOMQUOTA\n";
      close (OUTFILE);
      push(@donedom,$domain);
    }
    #if we didnt create this user yet, somewhere else, sometime ago.
    if ($userdone ne 1) {
      #statistics :)
      $countvpopuser+=1;
      if ($SYSTEMQUOTA eq 1) {
        $arg = Quota::getqcarg($SYSDIR);
        ($block_curr, $block_soft, $block_hard, $block_timelimit,
            $inode_curr, $inode_soft, $inode_hard, $inode_timelimit) =
            Quota::query($arg,$sysuid);
      } else {
        $block_hard="";
      }
      if($block_hard ne "") {
        if ($block_hard < $MINQUOTA) {
          $block_hard=$MINQUOTA
        }
        $QUOTA="$block_hard" ."000S";
        if($DEBUG >= 10) {
          print("Creating User $sysuname\@$domain with quota $QUOTA \n");
        }
        `$VPOPMAILHOMEDIR/bin/vadduser -q $QUOTA  $sysuname\@$domain  $sysuname`;  
      } else {
        if ($DEFAULTQUOTA ne 0) {
          if($DEBUG >= 10) {
            print("Creating User $sysuname\@$domain with default quota $DEFAULTQUOTA \n");
          }
          `$VPOPMAILHOMEDIR/bin/vadduser -q $DEFAULTQUOTA  $sysuname\@$domain  $sysuname`;
        } else {
          if($DEBUG >= 10) {
            print("Creating User $sysuname\@$domain without quota \n");
          }
          `$VPOPMAILHOMEDIR/bin/vadduser $sysuname\@$domain  $sysuname`;
        }
      }
      #update the vpopmail pasword with the system password
      $dbh->do("UPDATE vpopmail SET pw_passwd='$syspass'  where pw_name='$sysuname' and pw_domain='$domain'");
      $sth = $dbh->prepare("SELECT pw_dir FROM  vpopmail  where pw_name='$sysuname'  and pw_domain='$domain'");
      $sth->execute;
      while (my $ref = $sth->fetchrow_arrayref) {
        $mdir= $$ref[0];
      }
      $sth->finish;
      #copymails to user Maildir converting...
      $MAILBOXDIR="$SYSDIR/$INBOX";
      if ($DEBUG >= 20) {
        print("User mail file $MAILBOXDIR \n");
        sleep($SLEEPTIME);
      }
      if ( -e "$MAILBOXDIR" ) { # if user has any mail in spool
        open(MAILSPOOL, "<$MAILBOXDIR") || next;
        $i = time;
        if($DEBUG >= 10) {
          print("Copying and converting $sysuname mail to $mdir \n");
        }
        while(<MAILSPOOL>) {
          if (/^From /) {
            $filename = sprintf("%s/Maildir/new/%d.$$.mbox",$mdir, $i);
            open(MBOX, ">$filename") || die("Unable to create new message");;
            $i++;
            next;
          } #if ends
          s/^>From /From /;
          print MBOX || die ("Unable to write to new message");
        } #while mailspool ends
        close(MAILSPOOL);
        close(MBOX);
      } # if -e $MAILBOXDIR ends
      push(@doneuser,$sysuname);
      if ($DUPLICATE ne 0 && $domain eq $DEFAULTDOMAIN) {
        push(@doneuser1,$sysuname);
      }
      if ($domain eq $DEFAULTDOMAIN) {
        #for statistics
        $countdefaultdomain+=1;
      } 
    }
  }
}

