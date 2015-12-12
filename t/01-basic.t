use 5.10.1;
use strict;
use warnings;

use Test::More tests=>27;

BEGIN { use_ok( 'Ossec::Log::Parse' ); }

my $parse = Ossec::Log::Parse->new('logs/alerts.log');
my $alert = $parse->getAlert();
is(scalar keys %$alert, 15, 'Number of entries');
is($alert->{'ts'}, '1443175627.1028', 'ts');
is($alert->{'ts.human'}, '2015 Sep 25 06:07:07', 'ts.human');
is($alert->{'type'}, 'mail', 'type');
is($alert->{'group'}, 'syslog,fts,authentication_success', 'group');
is($alert->{'agent.name'}, 'i7dev', 'agent.name');
is($alert->{'agent.ip'}, '10.0.0.4', 'agent.ip');
is($alert->{'location'}, '/var/log/auth.log', 'location');
is($alert->{'rule.id'}, '10100', 'rule.id');
is($alert->{'rule.level'}, '4', 'rule.level');
is($alert->{'rule.comment'}, 'First time user logged in', 'rule.comment');
is($alert->{'source.ip'}, '10.0.0.2', 'source.ip');
is($alert->{'user'}, 'phirelight', 'user');
is($alert->{'full_log'}, 'Sep 25 06:07:06 i7dev sshd[17673]: Accepted publickey for phirelight from 10.0.0.2 port 44857 ssh2: RSA 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00', 'full_log');

$alert = $parse->getAlert();
is(scalar keys %$alert, 15, 'Number of entries');
is($alert->{'ts'}, '1443175106.517', 'ts');

$alert = $parse->getAlert();
is($alert, undef, 'EOF');
