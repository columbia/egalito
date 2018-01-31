#!/usr/bin/perl

if(@ARGV < 1) {
    die "Usage: $0 input-elf [--verbose] [[-]section1] [[-]section2] [...]\n";
}
my $filename = shift @ARGV;

# first, figure out instruction boundaries in the target
my @byteinfo = ();
my %bytelookup = ();
my @codesections = ('.text', '.plt');
foreach $sec (@codesections) {
	open(PIPE, "/usr/bin/objdump -wd -j .text $filename|") or die;
	for(1..7) { <PIPE> }  # skip header lines
	while(my $line = <PIPE>) {
		if($line =~ /\s*(\S+):\s+([^\t]+)\t/) {
			my $address = hex("0x$1");
			my $bytes = $2;
			my $count = 0;
			while($bytes =~ /\S\S/g) { $count ++ }
			#print "$address [$bytes] $count\n";

			push @byteinfo, [ $address, $count ];

			for(my $i = $address; $i < $address + $count; $i ++) {
				$bytelookup{$i} = $#byteinfo;
			}
		}
	}
	close PIPE;
}

my $verbose = 0;
# figure out which sections we should print
my %allowed = ();
my %excluded = ();
for my $arg (@ARGV) {
	if($arg =~ /^--verbose/) {
		$verbose = 1;
	}
    elsif($arg =~ /^-(.*)/) {
        $excluded{$1} = 1;
    }
    else {
        $allowed{$arg} = 1;
    }
}

#print "allowed: ".join(' ',keys(%allowed))."\n";
#print "excluded: ".join(' ',keys(%excluded))."\n";

# first, extract symbols, mapping name to address
my %syms = ();
open(PIPE, "/usr/bin/nm -f posix $filename 2>/dev/null|") or die;
while(my $line = <PIPE>) {
    if($line =~ /^(\S+) \S (\S+)/) {
        $syms{$1} = hex("0x$2");
    }
    # skip undefined symbols of type 'U', they have no address
}
close PIPE;

# extract address of sections
open(PIPE, "/usr/bin/readelf -WS $filename 2>/dev/null|") or die;
while(my $line = <PIPE>) {
    #   [15] .text             PROGBITS        0000000000000530 000530 0001a2 00  AX  0   0 16
    if($line =~ /^\s*\[\s*\d+\] (\.\S+)\s+\S+\s+(\S+)/) {
        #print "section $1 $2\n";
        $syms{$1} = hex("0x$2");
    }
}
close PIPE;

sub should_print_section($) {
	# hard code the egalito case for convinience
	return 0 if($_[0] =~ /\S*debug\S*/);
	return 0 if($_[0] =~ /.rela.eh_frame/);
    return 0 if($excluded{$_[0]});
    return 0 if(%allowed > 0 && !$allowed{$_[0]});
    return 1;
}

# now resolve each relocation
my $currentsection = '';
open(PIPE, "/usr/bin/readelf -Wr $filename|") or die;
while(my $line = <PIPE>) {
    chomp $line;
    if($line =~ /^Relocation section '([^']+)'/) {
        print "relocation section: $1\n" if should_print_section($1) and $verbose;
        $currentsection = $1;
		next;
    }

	next if !should_print_section($currentsection);

    if($line =~ /Offset\s+Info\s+Type/ || $line =~ /^\s*$/) {
        # skip
    }
    # 000000600ff0  000200000006 R_X86_64_GLOB_DAT 0000000000000000 __libc_start_main@GLIBC_2.2.5 + 0
    elsif($line =~ /^(\S+)\s+\S+\s+(\S+)\s+(\S+)\s*(.*?)$/) {
		print ">>>$line\n" if $verbose;
        my ($source, $type, $target, $symbolexpr) = (hex("0x$1"), $2, hex("0x$3"), $4);
        my $name = '';
		next if $type eq 'R_X86_64_COPY';

        if($symbolexpr =~ /^(\S+) \+ 0/) {
            $name = $1;
        }
        elsif($symbolexpr =~ /^\S+$/) {
            $name = $symbolexpr;
        }
        elsif($symbolexpr =~ /^(\S+) ([-+]) (\S+)/ && defined($syms{$1})) {
            my $addend = hex("0x$3");
            $addend = -$addend if($2 eq '-');
			if($type eq 'R_X86_64_PC32') {
				unless(defined($bytelookup{$source})) {
					die "instruction not found for this source?";
				}
				my $index = $bytelookup{$source};
				my $addr = $byteinfo[$index]->[0];
				my $size = $byteinfo[$index]->[1];
				# S + A - P + RIP@decode
				$target = $syms{$1} + $addend - $source + $addr + $size;
			}
			elsif($type eq 'R_X86_64_64') {
				$target = $syms{$1} + $addend;
			}
        }
        else {
            #print "??? ($symbolexpr)\n";
        }

        if($target != 0) {
			printf("    0x%-20x 0x%-20x %s\n", $source, $target, $name);
        }
    }
}
close PIPE;
