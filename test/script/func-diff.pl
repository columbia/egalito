#!/usr/bin/perl

my $filename = $ARGV[0];
my $list1 = $ARGV[1];
my $list2 = $ARGV[2];

#parse output from readelf
open(LIST1, $list1) or die;
my %funcs = ();
while(my $line = <LIST1>) {
	if ($line =~ /\s+\S+\s+(\S+)\s+(\S+)/) {
		my $addr = hex("0x$1");
		my $size = hex("0x$2");
		#printf("%08lx %08lx\n", $addr, $size);
		$funcs{$addr} = $size;
	}
	else {
		print("error: $line");
		break;
	}
}
close LIST1;

#parse output from etshell
open(LIST2, $list2) or die;
my %egalito_funcs = ();
while(my $line = <LIST2>) {
	if ($line =~ /(\S+)\s+(\S+)/) {
		my $addr = hex("$1");
		my $size = hex("$2");
		#printf("%08lx %08lx\n", $addr, $size);
		$egalito_funcs{$addr} = $size;
	}
	else {
		print("error: $line");
		break;
	}
}
close LIST2;

print("=== missing? ===\n");
for my $addr (sort {$a<=>$b} keys %funcs) {
	my $size = $funcs{$addr};
	unless(defined($egalito_funcs{$addr})) {
		printf("%08lx %08lx\n", $addr, $size);
		`echo "disass $addr" | gdb -x disass.gdb $filename`
	}
}

print("=== over-split? ===\n");
for my $addr (sort {$a<=>$b} keys %egalito_funcs) {
	my $size = $egalito_funcs{$addr};
	unless(defined($funcs{$addr})) {
		printf("%08lx %08lx\n", $addr, $size);
		`echo "disass $addr" | gdb -x disass.gdb $filename`
	}
}
