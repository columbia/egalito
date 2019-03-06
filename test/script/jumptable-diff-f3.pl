#!/usr/bin/perl

die "Usage: $0 symbol-table list1 list2\n" unless @ARGV == 3;
my $tablefile = $ARGV[0];
my $list1 = $ARGV[1];
my $list2 = $ARGV[2];

# read symbol information from library
# open(NM, "/usr/bin/nm $library|") or die;
# my %symbols = ();
# my %addresses = ();
# while(my $nm = <NM>) {
    # next unless $nm =~ /(\S+) [tTwW] (\S+)/;
    # my $address = hex("0x$1");
    # $symbols{$2} = $address;
    # push @{ $addresses{$address} }, $2;
# 
    # my $name = $2;
    # if($name =~ s/\@GLIBC_2.*//) {
        # $symbols{$name} = $address;
        # push @{ $addresses{$address} }, $name;
    # }
# }
# close NM;

my %symbols = ();
my %addresses = ();
open(ST, $tablefile) or die;
while(my $sym = <ST>) {
    $sym =~ /0x(\S+) 0x(\S+) (\S+)/;
    my $address = hex("0x$1");
    $symbols{$3} = $address;
    push @{ $addresses{$address} }, $3;

    my $name = $3;
    if($name =~ s/\@GLIBC_2.*//) {
        $symbols{$name} = $address;
        push @{ $addresses{$address} }, $name;
    }

    $name = $3;
    if($name =~ s/constprop.0/constprop/) {
        $symbols{$name} = $address;
        push @{ $addresses{$address} }, $name;
    }
}
close ST;

# slurp jumptable data from files
open(LIST1, $list1) or die;
my %tables1 = ();
while(my $line = <LIST1>) {
    next unless $line =~ /\[(\S+)\] .* (\d+) entries$/;

    $tables1{$1} = $2;
}
close LIST1;

open(LIST2, $list2) or die;
my %tables2 = ();
while(my $line = <LIST2>) {
    next unless $line =~ /\[(\S+)\] .* (\d+) entries$/;

    $tables2{$1} = $2;
}
close LIST2;

# diff left side then right side
for my $key (sort keys %tables1) {
    my $found = 0;
    my $address = defined $symbols{$key} ? $symbols{$key} : 0;
    for my $k (@{ $addresses{$address} }) {
        if(defined $tables2{$k} and $tables1{$key} == $tables2{$k}) {
            $found = 1;
        }
    }

    printf "<<< 0x%08x [%s] has %d entries\n", $address, $key, $tables1{$key} if !$found;
}

for my $key (sort keys %tables2) {
    my $found = 0;
    my $address = defined $symbols{$key} ? $symbols{$key} : 0;
    for my $k (@{ $addresses{$address} }) {
        if(defined $tables1{$k} and $tables2{$key} == $tables1{$k}) {
            $found = 1;
        }
    }

    printf ">>> 0x%08x [%s] has %d entries\n", $address, $key, $tables2{$key} if !$found;
}
