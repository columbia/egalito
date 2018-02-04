#!/usr/bin/perl

die "Usage: $0 elf list1 list2\n" unless @ARGV == 3;
my $filename = $ARGV[0];
my $list1 = $ARGV[1];
my $list2 = $ARGV[2];

# read symbol information from elf file
open(NM, "/usr/bin/nm $filename|") or die;
my %symbols = ();
my %addresses = ();
while(my $nm = <NM>) {
    next unless $nm =~ /(\S+) [tTwW] (\S+)/;
    my $address = hex("0x$1");
    $symbols{$2} = $address;
    push @{ $addresses{$address} }, $2;

    my $name = $2;
    if($name =~ s/\@GLIBC_2.*//) {
        $symbols{$name} = $address;
        push @{ $addresses{$address} }, $name;
    }
}
close NM;

my @relocationinfo = ();
my %relocations = ();
open(PIPE, "/usr/bin/readelf -Wr $filename-q|") or die;
while(my $line = <PIPE>) {
	chomp $line;
    next if($line =~ /^Relocation section '([^']+)'/);
    next if($line =~ /Offset\s+Info\s+Type/ || $line =~ /^\s*$/);

    if($line =~ /^(\S+)\s+\S+\s+(\S+)\s+(\S+)\s*(.*?)$/) {
        my ($type, $symvalue, $symbolexpr) = (hex("0x$1"), $2, hex("0x$3"), $4);
		#printf(">>> %x %s\n", $source, $symbolexpr);
		push @relocationinfo, [ $type, $symvalue, $symbolexpr ];
		$relocations{$source} = $#relocationinfo - 1;
	}
}
close PIPE;

#for (keys %relocations) {
#	printf("    %x %x %s\n", $_, $relocations{$_}, $relocationinfo[$relocations{$_}]->[3]);
#}

open(LIST1, $list1) or die;
my %links1 = ();
while(my $line = <LIST1>) {
    next unless $line =~ /(\S+)\s+(\S+)/;
	my $s = hex($1);
	my $d = hex($2);

    $links1{$s} = $d;
}
close LIST1;

open(LIST2, $list2) or die;
my %links2 = ();
while(my $line = <LIST2>) {
    next unless $line =~ /(\S+)\s+(\S+)/;

	my $s = hex($1);
	my $d = hex($2);

    $links2{$s} = $d;
}
close LIST2;

# diff left side then right side
for my $key (sort keys %links1) {
	unless(defined($links2{$key})) {
		printf("only %s<<< 0x%08x -> 0x%08lx\n", $list1, $key, $links1{$key});
		if(defined($relocations{$key})) {
			my $index = $relocations{$key};
			printf("  w/ relocation %s %x %s\n",
				$relocationinfo[$index]->[1],
				$relocationinfo[$index]->[2],
				$relocationinfo[$index]->[3]);
		}
	}
}

for my $key (sort keys %links2) {
	unless(defined($links1{$key})) {
		printf "only %s>>> 0x%08x -> 0x%08lx\n", $list2, $key, $links2{$key};
		if(defined($relocations{$key})) {
			my $index = $relocations{$key};
			printf("  w/ relocation %s %x %s\n",
				$relocationinfo[$index]->[1],
				$relocationinfo[$index]->[2],
				$relocationinfo[$index]->[3]);
		}
	}
}
