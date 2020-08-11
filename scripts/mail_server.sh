apt update
apt upgrade
apt install ifupdown
apt purge netplan.io

hostnamectl --set-hostname mail.domain

apt install -y amavisd-new certbot dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql dovecot-sieve haveged mailutils mariadb-server opendkim opendkim-tools p7zip postfix postfix-mysql postgrey spamassassin razor pyzor

openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/vmail

mkdir -p /var/vmail
chown -R vmail:vmail /var/vmail
############################################## MYSQL CONFIGURATION ######################################3
mysql_secure_installation

mysql -u root -p < password

CREATE DATABASE `postfix`;
GRANT SELECT ON `postfix`.* TO `postfix`@`127.0.0.1` IDENTIFIED BY 'p0stf1x';
FLUSH PRIVILEGES;
USE postfix;

CREATE TABLE `domains` (
  `id` int(11) NOT NULL auto_increment,
  `domain` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `users` (
  `id` int(11) NOT NULL auto_increment,
  `domain` int(11) NOT NULL,
  `password` varchar(106) NOT NULL,
  `email` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  FOREIGN KEY (domain) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `aliases` (
  `id` int(11) NOT NULL auto_increment,
  `domain` int(11) NOT NULL,
  `source` varchar(100) NOT NULL,
  `destination` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  FOREIGN KEY (domain) REFERENCES domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

##################################################### POSTFIX #########################################

#####################             etc/postfix/master.cf:

submission inet n       -       y      -       -       smtpd
  -o smtpd_tls_security_level=encrypt
  -o content_filter=
amavis           unix    -       -       n       -       2       smtp
  -o smtp_send_xforward_command=yes
  -o smtp_tls_security_level=none
127.0.0.1:10025  inet    n       -       n       -       -       smtpd
  -o content_filter=
#############################   END

#############################      /etc/postfix/main.cf:
myhostname = mail.domain
myorigin = /etc/mailname
mydestination = localhost ###### Write fqdn domain if it don't use in to mysql database
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
smtpd_banner = $myhostname ESMTP
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all
message_size_limit = 20480000

biff = no
append_dot_mydomain = no
# Uncomment the next line to generate "delayed mail" warnings
#delay_warning_time = 4h
readme_directory = no
compatibility_level = 2
################# TLS parameters  ################
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls=yes
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_sasl_auth_enable = yes
smtpd_sasl_path = private/auth
smtpd_sasl_type = dovecot

####################### RULES #################
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_hostname, reject_non_fqdn_hostname, reject_non_fqdn_sender, reject_non_fqdn_recipient, reject_unknown_sender_domain, reject_unknown_recipient_domain, reject_unauth_destination, check_policy_service inet:[127.0.0.1]:10023
content_filter = amavis:[127.0.0.1]:10024
non_smtpd_milters = inet:[127.0.0.1]:12301
smtpd_milters=inet:[127.0.0.1]:12301
smtp_header_checks = regexp:/etc/postfix/header_checks
smtp_mime_header_checks = regexp:/etc/postfix/header_checks
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
virtual_alias_maps = mysql:/etc/postfix/mysql_virtual_alias_emails.cf, mysql:/etc/postfix/mysql_virtual_alias_maps.cf
virtual_gid_maps = static:5000
virtual_mailbox_base = /var/vmail
virtual_mailbox_domains = mysql:/etc/postfix/mysql_virtual_mailbox_domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql_virtual_mailbox_maps.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_uid_maps = static:5000
#############################   END

nano /etc/postfix/mysql_virtual_mailbox_domains.cf

user = postfix
password = p0stf1x
hosts = 127.0.0.1
dbname = postfix
query = SELECT 1 FROM domains WHERE domain='%s'

nano /etc/postfix/mysql_virtual_mailbox_maps.cf

user = postfix
password = p0stf1x
hosts = 127.0.0.1
dbname = postfix
query = SELECT 1 FROM users WHERE email='%s'

nano /etc/postfix/mysql_virtual_alias_maps.cf

user = postfix
password = p0stf1x
hosts = 127.0.0.1
dbname = postfix
query = SELECT destination FROM aliases WHERE source='%s'

nano /etc/postfix/mysql_virtual_alias_emails.cf

user = postfix
password = p0stf1x
hosts = 127.0.0.1
dbname = postfix
query = SELECT email FROM users WHERE email='%s'

nano /etc/postfix/header_checks

    /^Received:.*with ESMTP/        IGNORE
    /^X-Mailer:/                    IGNORE
    /^User-Agent:/                  IGNORE
    /^Mime-Version:/                IGNORE

###Generate Postfix map:
postmap /etc/postfix/header_checks

###Finalize Postfix Setup
###Generate alias map:
newaliases
systemctl restart postfix
#=======================
###########################################################
#######################################DOVECOT
########################################################

nano /etc/dovecot/dovecot.conf

listen = *
mail_location = maildir:/var/vmail/%d/%n/
protocols = imap lmtp
ssl = required
ssl_cert = < /etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = < /etc/ssl/private/ssl-cert-snakeoil.key
ssl_prefer_server_ciphers = yes

namespace inbox {
  inbox = yes
  location =
  separator = /

  mailbox Drafts {
    auto = subscribe
    special_use = \Drafts
  }

  mailbox "Sent Messages" {
    auto = subscribe
    special_use = \Sent
  }
  mailbox Junk {
    auto = subscribe
    special_use = \Junk
  }

  mailbox "Deleted Messages" {
    auto = subscribe
    special_use = \Trash
  }

  mailbox Archive {
    auto = subscribe
    special_use = \Archive
  }

  mailbox Notes {
    auto = subscribe
  }
}


passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }

  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }

  user = dovecot
}

service auth-worker {
  user = vmail
}

service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    group = postfix
    mode = 0600
    user = postfix
  }
}

protocol lmtp {
  postmaster_address = postmaster@domain
  hostname = mail.domain
  mail_plugins = sieve
}

plugin {
  sieve_before = /etc/dovecot/spam.sieve
}
#================ END

nano /etc/dovecot/dovecot-sql.conf.ext

driver = mysql
connect = host=127.0.0.1 dbname=postfix user=postfix password=p0stf1x
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';
#================END

nano /etc/dovecot/spam.sieve

require ["fileinto", "imap4flags"];

if header :contains "X-Spam-Flag" "YES" {
  setflag "\\Seen";
  fileinto "Junk";
  stop;
}
#=================END

sievec /etc/dovecot/spam.sieve
systemctl restart dovecot

#================ END DOVECOT

################################################ Postgrey

wget -O /etc/postgrey/whitelist_clients https://raw.githubusercontent.com/schweikert/postgrey/master/postgrey_whitelist_clients
systemctl restart postgrey
#====================== END POSTGREY

################################################### OpenDKIM
cp /etc/opendkim.conf{,.orig}
echo "" >/etc/opendkim.conf
nano /etc/opendkim.conf

    AutoRestart             Yes
    AutoRestartRate         10/1h
    UMask                   002
    Syslog                  yes
    SyslogSuccess           Yes
    LogWhy                  Yes

    Canonicalization        relaxed/simple

    ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
    InternalHosts           refile:/etc/opendkim/TrustedHosts
    KeyTable                refile:/etc/opendkim/KeyTable
    SigningTable            refile:/etc/opendkim/SigningTable

    Mode                    sv
    PidFile                 /var/run/opendkim/opendkim.pid
    SignatureAlgorithm      rsa-sha256

    UserID                  opendkim:opendkim
    Socket                  inet:12301@localhost

#Create config directory:
mkdir -p /etc/opendkim
nano /etc/opendkim/TrustedHosts
127.0.0.1
localhost
nano /etc/opendkim/KeyTable
mail2020._domainkey.domain domain:mail2020:/etc/opendkim/keys/domain/mail2020.private
nano /etc/opendkim/SigningTable
*@domain mail2020._domainkey.domain
mkdir -p /etc/opendkim/keys/domain
opendkim-genkey -s mail2020 -d domain -D /etc/opendkim/keys/domain
chown opendkim:opendkim /etc/opendkim/keys/domain/mail2020.private
chmod 0400 /etc/opendkim/keys/domain/mail2020.private
systemctl restart opendkim
#####Get DKIM record from /etc/opendkim/keys/<DOMAIN>/mail2019.txt and create a new DNS record from it.
#############============ END DKIM

################################ AMAVIS

usermod -aG vmail amavis

nano /etc/amavis/conf.d/50-user

use strict;

$smtp_connection_cache_on_demand = 0;
$smtp_connection_cache_enable = 0;

@bypass_spam_checks_maps = (
   \%bypass_spam_checks, \@bypass_spam_checks_acl, \$bypass_spam_checks_re);

$sa_tag_level_deflt  = -999;
$sa_tag2_level_deflt = 2.0;
$sa_kill_level_deflt = 4.0;
$sa_dsn_cutoff_level = 5.0;

$final_spam_destiny       = D_PASS;

$undecipherable_subject_tag=undef;

@lookup_sql_dsn = (
  ['DBI:mysql:database=postfix;host=127.0.0.1;port=3306',
   'postfix',
   'p0stf1x']);

$sql_select_policy = 'SELECT domain FROM domains WHERE CONCAT("@",domain) IN (%k)';

1;
#=========== END

systemctl restart amavis

#============================= END AMAVIS

############################################### SPAMASSASSIN

cd /tmp
wget http://untroubled.org/spam/2019-08.7z
p7zip -d 2019-08.7z
chown -R amavis:amavis 2019/
cd -

su amavis -c 'sa-learn --progress --spam /tmp/2019/'

crontab -e):

@hourly su amavis -c 'sa-learn --ham /var/vmail/*/*/cur/'
@hourly su amavis -c 'sa-learn --spam /var/vmail/*/*/.Junk/cur/'

#=============== END SPAMASSASSIN

######################################## Razor (& Pyzor)

su amavis -c 'razor-admin -create'
su amavis -c 'razor-admin -register'
su amavis -c 'razor-admin -discover'

#=============== END RAZOR

######################################## Domains, Mailboxes & Aliases

su vmail -c 'mkdir -p -m 0770 /var/vmail/domain'

INSERT INTO `postfix`.`domains` (`id` ,`domain`) VALUES ('1', 'domain');

INSERT INTO `postfix`.`users` (`id`, `domain`, `password` , `email`) VALUES ('1', '1', ENCRYPT('2608747', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'citcer@domain');

INSERT INTO `postfix`.`aliases` (`id`, `domain`, `source`, `destination`) VALUES ('1', '1', '@domain', 'citcer@domain');

doveadm mailbox create -u citcer@domain INBOX

#================================================================ END END

############# Client Configuration
#
#    IMAP:
#
#        Server: <FQDN>
#        Port: 993
#        Encryption: SSL/TLS
#
#    SMTP:
#
#        Server: <FQDN>
#        Port: 587
#        Encryption: STARTTLS




