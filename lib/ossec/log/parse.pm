package ossec::log::parse;

use strict;
use warnings;
use autodie;
use Carp;
use Scalar::Util qw/openhandle/;

our $VERSION = '0.1.0';

BEGIN {
    my @accessors = qw/fh file/;
    for my $accessor ( @accessors ) {
        no strict 'refs';
        *$accessor = sub {
            my $self = shift;
            return $self->{$accessor};
        }
    }
}

sub new {
    my $class = shift;
    my $arg = shift;

    my $self = {};

    if ( !defined($arg) ) {
        $self->{diamond} = 1;
    } elsif ( ref($arg) eq 'HASH' ) {
        $self = $arg;
    } elsif ( defined(openhandle($arg)) ) {
        $self->{fh} = $arg;
    } else {
        $self->{file} = $arg;
    }

    bless $self, $class;

    if ( defined($self->{file}) && !(defined($self->{fh})) ) {
        unless ( -f $self->{file} ) {
            carp("Could not open ".$self->{file});
            return 0;
        }
        open( my $fh, "<", $self->{file} ) or croak("Cannot open ".$self->{file});
        $self->{fh} = $fh;
    }

    if ( !defined($self->{fh}) && ( !defined($self->{diamond}) || !$self->{diamond} ) ) {
        carp("No filename given in constructor. Aborting");
        return 0;
    }

    return $self;
}

sub getAlert {

    my $self = shift;
    my $fh = $self->{fh};

    my %event;
    my $position = 0;

    while ( my $line = defined($fh) ? <$fh> : <> ) {

        chomp($line);

        if ($line =~ m/^\*\* Alert (\d+\.\d+):(.*)-(.*)/) {
            $event{'ts-unix'} = $1;
            $event{'type'} = $2;
            $event{'group'} = $3;
            # clean up variables
            $event{'type'} =~ s/^\s+|\s+$//g; # strip leading/trailing whitespace
            $event{'group'} =~ s/^\s+|\s+$//g;
            $event{'group'} =~ s/,$//g; # strip trailing comma
            $position = 1;
            next;
        }
        if ($position > 0) {
            $position++;
            if ($position == 2) {
                if ($line =~ m!(\d+ \w+ \d+ \d+:\d+:\d+) \((.*)\) (\S+)->(.*)!) { # event from remote agent
                    $event{'ts-human'} = $1;
                    $event{'agent'} = $2;
                    $event{'agent-ip'} = $3;
                    $event{'location'} = $4;
                }
                elsif ($line =~ m!(\d+ \w+ \d+ \d+:\d+:\d+) (\S+)->(.*)!) { # event from local agent
                    $event{'ts-human'} = $1;
                    $event{'agent'} = $2;
                    $event{'agent-ip'} = undef;
                    $event{'location'} = $3;
                }
                $event{'2'} = $line;
                next;
            }
            elsif ($position == 3) {
                if ($line =~ /^Rule: (\d+) \(level (\d+)\) -> '(.*)'$/) {
                    $event{'rule.id'} = $1;
                    $event{'rule.level'} = $2;
                    $event{'rule.comment'} = $3;
                    # clean up variable
                    $event{'rule.comment'} =~ s/\.$//; # remove any trailing period
                }
                $event{'3'} = $line;
                next;
            }
            elsif ($line !~ m/^$/ ) {
                if ($event{'full_log'} ) {
                    $event{'full_log'} = "$event{'full_log'}\n$line";
                }
                else {
                    $event{'full_log'} = $line;
                }
            }
            else {
                $position = 0;
                return \%event;
            }
        }
    }
}

1;

