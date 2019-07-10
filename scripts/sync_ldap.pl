#!/usr/local/bin/perl -w

use lib '/opt/zimbra/common/lib/perl5';
use Zimbra::LDAP;
use Zimbra::ZmClient;
use Net::LDAP;
use YAML::Tiny;
use Getopt::Long;
use Data::UUID;
use utf8;
use Data::Dumper;

my $conf = {};
my $opt = {
  config => '/opt/zimbra/conf/ldap_sync.yml'
};

GetOptions (
  'c|config=s'  => \$opt->{config},
);

# Check if the config file exists, and if so, parse it
# and load it in $conf
if ( -e $opt->{config} ) {
  print "Reading config file " . $opt->{config} . "\n";
  my $yaml = YAML::Tiny->read( $opt->{config} )
    or die "Config file " . $opt->{config} . " is invalid\n";

  if ( not $yaml->[0] ) {
    die "Config file " . $opt->{config} . " is invalid\n";
  }

  $conf = $yaml->[0];
} else {
  # If the config file doesn't exist, just die
  die "Config file " . $opt->{config} . " doesn't exist\n";
}

my $zim_ldap = Zimbra::LDAP->new();
my $uuid     = Data::UUID->new();
my $exit     = 0;
my $res;

DOMAIN: foreach my $domain ( keys $conf ) {
  print "Checking domain $domain\n";
  # Search in Zimbra LDAP if the required domain exists
  $res = $zim_ldap->ldap->search(
    filter => "(&(objectClass=zimbraDomain)(zimbraDomainName=$domain)(!(zimbraDomainAliasTargetId=*)))"
  );
  if ( $res->code ) {
    print "Couldn't lookup zimbra domains : " . $res->error . "\n";
    $exit = 255;
  }

  # We must have exactly 1 result
  if ( scalar $res->entries == 0 ) {
    if ( yaml_bool($conf->{$domain}->{zimbra}->{create_if_missing}) ) {
      print "Creating domain $domain";
      ZmClient::sendZmprovRequest( "createDomain $domain " . build_domain_attrs($conf->{$domain}) );
    } else {
      print "Domain $domain doesn't exist, you must create it first\n";
      $exit = 255;
    }
  } elsif ( scalar $res->entries gt 1 ) {
    die "Found several domains matching, something is wrong, please check your settings\n";
  }

  # Get LDAP entry representing the domain
  my $domain_entry = ($res->entries)[0];

  # Check if auth is set to ad or ldap
  if ( not $domain_entry->exists('zimbraAuthMech') or $domain_entry->get_value('zimbraAuthMech') !~ m/^ad|ldap$/) {
    if ( yaml_bool($conf->{$domain}->{zimbra}->{setup_ldap_auth}) ) {
      ZmClient::sendZmprovRequest( "modifyDomain $domain " . build_domain_attrs( $conf->{$domain} ) );
    } else {
      die "Domain " . $conf->{$domain}->{zimbra}->{domain} . " must be configured for LDAP or AD external authentication first\n";
    }
  }

  print "Trying to connect to " . join( ' or ', @{ $conf->{$domain}->{ldap}->{servers} } ) . "\n";

  my $ext_ldap = Net::LDAP->new( [ @{ $conf->{$domain}->{ldap}->{servers} } ] );
  if ( not $ext_ldap ) {
    print "Error while connecting to LDAP : $@\n";
    $exit = 255;
    next DOMAIN;
  }

  print "Connection succeeded\n";

  if ( yaml_bool( $conf->{$domain}->{ldap}->{start_tls} ) ) {
    print "Trying to switch to a secured connection using StartTLS\n";
    $res = $ext_ldap->start_tls( verify => 'require' );
    if ( $res->code ) {
      print "StartTLS failed : " . $res->error . "\n";
      $exit = 255;
      next DOMAIN;
    }

    print "StartTLS succeeded\n";
  }

  if ( defined $conf->{$domain}->{ldap}->{bind_dn} and defined $conf->{$domain}->{ldap}->{bind_pass} ) {
    print "Trying to bind as " . $conf->{$domain}->{ldap}->{bind_dn} . "\n";
    $ext_ldap->bind(
      $conf->{$domain}->{ldap}->{bind_dn},
      password => $conf->{$domain}->{ldap}->{bind_pass}
    );
    if ( $res->code ) {
      print "StartTLS failed : " . $res->error . "\n";
      $exit = 255;
      next DOMAIN;
    }

    print "Bind succeeded\n";
  }

  print "Searching for potential users in " . $conf->{$domain}->{users}->{base} . " matching filter " . $conf->{$domain}->{users}->{filter} . "\n";

  my $ext_user_search = $ext_ldap->search(
     base   => $conf->{$domain}->{users}->{base},
     filter => $conf->{$domain}->{users}->{filter},
     attrs  => [ keys $conf->{$domain}->{users}->{attr_map}, ( $conf->{$domain}->{users}->{key} ) ]
  );
  if ( $ext_user_search->code ) {
    print "Search failed : " . $ext_user_search->error . "\n";
    $exit = 255;
    next DOMAIN;
  }

  print "Found " . scalar $ext_user_search->entries . " users in external LDAP\n";

  print "Searching for users in Zimbra\n";

  my $zim_user_search = $zim_ldap->ldap->search(
    base   => 'ou=people,' . $domain_entry->dn,
    filter => '(&(objectClass=zimbraAccount)(!(|' .
                '(mail=' . $zim_ldap->global->get_value('zimbraSpamIsSpamAccount') . ')' .
                '(mail=' . $zim_ldap->global->get_value('zimbraSpamIsNotSpamAccount') . ')' .
                '(mail=' . $zim_ldap->global->get_value('zimbraAmavisQuarantineAccount') . ')' .
                '(uid=galsync*)(uid=admin))))',
    attrs => [ ( map { $conf->{$domain}->{users}->{attr_map}->{$_} } keys $conf->{$domain}->{users}->{attr_map} ), ( 'uid', 'zimbraAccountStatus', 'zimbraAuthLdapExternalDn' ) ]
  );
  if ( $zim_user_search->code ) {
    print "Search failed : " . $zim_user_search->error . "\n";
    $exit = 255;
    next DOMAIN;
  }

  print "Found " . scalar $zim_user_search->entries . " users in Zimbra\n";

  print "Now comparing the accounts\n";

  my $ext_users = ldap2hashref( $ext_user_search, $conf->{$domain}->{users}->{key} );
  my $zim_users = ldap2hashref( $zim_user_search, 'uid' );

  # First loop : Check users which exist in external LDAP but not in Zimbra
  # or which exist in both but need to be updated
  foreach my $user ( keys $ext_users ) {

    if ( defined $zim_users->{$user} ) {
      # User exists in Zimbra, lets check its attribute are up to date
      my $attrs = '';
      foreach my $attr ( keys $conf->{$domain}->{users}->{attr_map} ) {
        if ( not defined $ext_users->{$user}->{$attr} and not defined $ext_users->{$user}->{$conf->{$domain}->{users}->{attr_map}->{$attr}} ) {
          # Attr does not exist in external LDAP and in Zimbra, not need to continue
          next;
        }
        if ( $conf->{$domain}->{users}->{attr_map}->{$attr} ne 'sn' and not defined $ext_users->{$user}->{$attr} ) {
          # If the attribute doesn't exist in external LDAP, we must remove it from Zimbra.
          # Except for sn which is mandatory
          $attrs .= '-' . $conf->{$domain}->{users}->{attr_map}->{$attr} . " '" . $zim_users->{$user}->{$conf->{$domain}->{users}->{attr_map}->{$attr}} . "' ";
        } elsif (
                  ( $conf->{$domain}->{users}->{attr_map}->{$attr} ne 'sn' and
                    $ext_users->{$user}->{$attr} ne ( $zim_users->{$user}->{$conf->{$domain}->{users}->{attr_map}->{$attr}} || '' )
                  ) ||
                  $conf->{$domain}->{users}->{attr_map}->{$attr} eq 'sn' and
                    defined $ext_users->{$user}->{$attr} and
                    $ext_users->{$user}->{$attr} ne ( $zim_users->{$user}->{$conf->{$domain}->{users}->{attr_map}->{$attr}} || '' )
                ) {
            my $value = $ext_users->{$user}->{$attr};
            $value =~ s/'/\\'/g;
            utf8::encode($value);
            $attrs .= $conf->{$domain}->{users}->{attr_map}->{$attr} . " '" . $value . "' ";
            print $ext_users->{$user}->{$attr} . " vs " . $zim_users->{$user}->{$conf->{$domain}->{users}->{attr_map}->{$attr}} . "\n";
        }
      }

      if ( not defined $zim_users->{$user}->{zimbraAuthLdapExternalDn} or $zim_users->{$user}->{zimbraAuthLdapExternalDn} ne $ext_users->{$user}->{dn} ) {
        my $value = $ext_users->{$user}->{dn};
        utf8::encode($value);
        $attrs .= " zimbraAuthLdapExternalDn '$value'";
      }

      if ( $attrs ne '' ) {
        # Some attribute must change, lets update Zimbra
        print "User $user has changed in external LDAP, updating it\n";
        print "Sending zmprov modifyAccount $user\@$domain $attrs\n";
        ZmClient::sendZmprovRequest( "modifyAccount $user\@$domain $attrs" );
      }

    } else {
      # User exists in external LDAP but not in Zimbra. We must create it
      print "User $user found in external LDAP but not in Zimbra. Will be created\n";
      my $attrs = '';
      foreach my $attr ( keys $conf->{$domain}->{users}->{attr_map} ) {
        next if (not defined $ext_users->{$user}->{$attr} or $ext_users->{$user}->{$attr} eq '');
        $attrs .= ' ' . $conf->{$domain}->{users}->{attr_map}->{$attr} . ' ' . $ext_users->{$user}->{$attr};
      }
      my $pass = $uuid->create_str;
      print "Sending zmprov createAccount $user\@$domain $pass $attrs\n";
      ZmClient::sendZmprovRequest( "createAccount $user\@$domain $pass $attrs" );
    }
  }

  # Now, we loop through the ZImbra user to check if they should be locked (if they don't exist in external LDAP anymore)
  foreach my $user ( keys $zim_users ) {
    if ( not defined $ext_users->{$user} and defined $zim_users->{$user}->{zimbraAccountStatus} and $zim_users->{$user}->{zimbraAccountStatus} =~ m/^active|lockout$/ ) {
      print "User $user doesn't exist in external LDAP anymore, locking it in Zimbra\n";
      print "Sending zmprov modifyAccount $user\@$domain zimbraAccountStatus locked\n";
      ZmClient::sendZmprovRequest( "modifyAccount $user\@$domain zimbraAccountStatus locked" );
    }
  }
}

# zmprov breaks terminal (no echo to your input after execution)
# fix it with a tset
system('tset');

sub ldap2hashref {
  my $search = shift;
  my $key    = shift;
  my $return = {};
  foreach my $entry ( $search->entries ) {
    $return->{lc $entry->get_value($key)}->{dn} = $entry->dn;
    foreach my $attr ( $entry->attributes ) {
      $return->{lc $entry->get_value($key)}->{$attr} = $entry->get_value($attr) if ($attr ne $key);
    }
  }
  return $return;
}

# Check YAML bool
sub yaml_bool {
  my $bool = shift;
  if ( $bool =~ m/^y|yes|true|1|on$/i ) {
    return 1;
  } else {
    return 0;
  }
}

sub build_domain_attrs {
  my $domain_conf = shift;
  my $attrs = "zimbraAuthMech " . $domain_conf->{ldap}->{type};
  $attrs .= " zimbraAuthMechAdmin " . $domain_conf->{ldap}->{type};
  if ( defined $domain_conf->{ldap}->{bind_dn} and defined $domain_conf->{ldap}->{bind_pass} ) {
     my $pass = $domain_conf->{ldap}->{bind_pass};
     $pass =~ s/'/\\'/g;
     $attrs .= " zimbraAuthLdapSearchBindDn '" . $domain_conf->{ldap}->{bind_dn} . "' zimbraAuthLdapSearchBindPassword '" . $pass . "'";
  }
  if ( defined $domain_conf->{users}->{filter} ) {
    $attrs = " zimbraAuthLdapSearchFilter '(&(" . $domain_conf->{users}->{key} . "=%u)(" . $domain_conf->{users}->{filter} . ")'";
  }
  $attrs .= " zimbraAuthLdapURL " . join( ' +zimbraAuthLdapURL', $domain_conf->{ldap}->{servers} );
  if ( defined $domain_conf->{ldap}->{start_tls} and yaml_bool($domain_conf->{ldap}->{start_tls}) ) {
    $attrs .= " zimbraAuthLdapStartTlsEnabled TRUE";
  }
  return $attrs;
}
