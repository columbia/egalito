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

# figure out section address and size
my @sectioninfo = ();
my %sectionlookup = ();
open(PIPE, "/usr/bin/readelf -SW $filename|") or die;
for(1..5) { <PIPE> }  # skip header lines
push @sectioninfo, [ 0, 0 ];
while(my $line = <PIPE>) {
	#  [28] .got              PROGBITS        000000000001ffa0 00ffa0 000048 08  WA  0   0  8
	if($line =~ /\s*\[\s*(\S+)\]\s+(\S+)\s+\S+\s+(\S+)\s+\S+\s+(\S+)/) {
		my $address = hex("0x$3");
		my $size = hex("0x$4");

		#printf("section [%d] %s 0x%08x - %08x\n", $1, $2, $address, $address + $size);
		push @sectioninfo, [ $address, $address + $size ];
		$sectionlookup{$2} = $#sectioninfo;
	}
}
close PIPE;

#print "allowed: ".join(' ',keys(%allowed))."\n";
#print "excluded: ".join(' ',keys(%excluded))."\n";

# first, extract symbols, mapping name to address
my %syms = ();
my %addrs = ();
open(PIPE, "/usr/bin/nm -f posix $filename 2>/dev/null|") or die;
while(my $line = <PIPE>) {
    if($line =~ /^(\S+) \S (\S+)/) {
        $addrs{$1} = hex("0x$2");
		$syms{hex("0x$2")} = $1;
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
        $addrs{$1} = hex("0x$2");
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

# keep track of relocation entries in .got for ARM
my %gotentries = ();
my $gotindex = $sectionlookup{".got"};
my $gotstart = $sectioninfo[$gotindex]->[0];
my $gotend = $sectioninfo[$gotindex]->[1];
#printf(".got: [0x%08x, 0x%08x]\n", $gotstart, $gotend);
sub inside_got($) {
	return 1 if($gotstart <= $_[0] and $_[0] < $gotend);
	return 0;
}

my $rodataindex = $sectionlookup{".rodata"};
my $rodatastart = $sectioninfo[$rodataindex]->[0];
my $rodataend = $sectioninfo[$rodataindex]->[1];
sub inside_rodata($) {
	return 1 if($rodatastart <= $_[0] and $_[0] < $rodataend);
	return 0;
}

sub add_got_entry($$) {
	#print("parsed got entries $_[0]\n") if $verbose;
	$gotentries{$_[0]} = $_[1];
	if($_[0] =~ /([a-z0-9_]+)@\S+/) {
		#print("non versioned got entries $1\n") if $verbose;
		$gotentries{$1} = $_[1];
	}
}

sub lookup_in_got($) {
	#print("lookup_in_got arg $_[0]\n");
	if(defined($gotentries{$_[0]})) {
		return $gotentries{$_[0]};
	}
	else {
		if($_[0] =~ /([a-z0-9_]+)@\S+/) {
			#print("checking non versioned symbol? $1\n");
			return $gotentries{$1};
		}
	}
	print("failed to lookup $_[0] in got\n") if $verbose;
	print "gotentries: ".join(' ',keys(%gotentries))."\n";
	return 0;
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
        my ($source, $type, $symvalue, $symbolexpr) = (hex("0x$1"), $2, hex("0x$3"), $4);
        my $name = '';
		my $handled = 1;
		next if $type eq 'R_X86_64_COPY';

		if($symbolexpr =~ /^\S+$/) {
            $name = $symbolexpr;
			$target = $symvalue;
        }
		elsif($type eq 'R_X86_64_GLOB_DAT' and $symbolexpr =~ /^(\S+) \+ 0/) {
			$target = $symvalue;
			if(inside_got($source)) {
				add_got_entry($1, $source);
				$handled = 0;
			}
		}
		elsif($type eq 'R_X86_64_RELATIVE') {
			if(inside_got($source)) {
				$gotentries{$syms{$symvalue}} = $source;
			}
			$handled = 0;
		}
		elsif($type eq 'R_AARCH64_RELATIVE') {
			if(inside_got($source)) {
				$gotentries{$syms{$symvalue}} = $source;
			}
			$handled = 0;
		}
		elsif($type eq 'R_AARCH64_GLOB_DAT' and $symbolexpr =~ /^(\S+) \+ 0/) {
			$target = $symvalue;
			if(inside_got($source)) {
				add_got_entry($1, $source);
				$handled = 0;
			}
		}
        elsif($symbolexpr =~ /^(\S+) ([-+]) (\S+)/) {
			if($type eq 'R_X86_64_REX_GOTPCRELX') {
				$target = lookup_in_got($1) + $addend;
			}
			elsif($type eq 'R_X86_64_GOTPCRELX') {
				$target = lookup_in_got($1) + $addend;
			}
			elsif($type eq 'R_X86_64_GOTPCREL') {
				$target = lookup_in_got($1) + $addend;
			}
			elsif($type eq 'R_AARCH64_ADR_GOT_PAGE') {
				$target = lookup_in_got($1) + $addend;
			}
			elsif($type eq 'R_AARCH64_LD64_GOT_LO1') {	# truncated even with -W
				$target = lookup_in_got($1) + $addend;
			}
			elsif(defined($addrs{$1})) {
				my $addend = hex("0x$3");
				$addend = -$addend if($2 eq '-');
				if($type eq 'R_X86_64_PC32') {
					if(defined($bytelookup{$source})) {
						my $index = $bytelookup{$source};
						my $addr = $byteinfo[$index]->[0];
						my $size = $byteinfo[$index]->[1];
						# S + A - P + RIP@decode
						$target = $symvalue + $addend - $source + $addr + $size;
					}
					else {
						# jump table entries are relative to the section
						die "not a jump table?" unless(inside_rodata($source));
						# for jump tables we can only compare the value
						$target = $symvalue + $addend - $source;
					}
				}
				elsif($type eq 'R_X86_64_64') {
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_AARCH64_CALL26') {
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_AARCH64_ADR_PREL_PG_') {	# truncated even with -W
					$target = $symvalue + $addend;	# to match egalito
				}
				elsif($type eq 'R_AARCH64_ADD_ABS_LO12') {
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_AARCH64_ABS64') {
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_AARCH64_LDST64_ABS_L') {	# truncated even with -W
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_AARCH64_LDST8_ABS_LO') {	# truncated even with -W
					$target = $symvalue + $addend;
				}
				elsif($type eq 'R_X86_64_PLT32') {
					if(defined($symvalue)) {
						#$target = $symvalue;
						my $index = $bytelookup{$source};
						my $addr = $byteinfo[$index]->[0];
						my $size = $byteinfo[$index]->[1];
						# S + A - P + RIP@decode
						$target = $symvalue + $addend - $source + $addr + $size;
					}
					else {
						$handled = 0;
					}
				}
				else {
					print "??? (type = $type)\n" if $verbose;
					$handled = 0;
				}
			}
			else {
				$handled = 0;
			}
        }
		elsif($target == 0) {
			$handled = 0;
		}
        else {
            print "??? (symbol expr = $symbolexpr)\n" if $verbose;
			$handled = 0;
        }

        if($handled != 0) {
			printf("    0x%-20x 0x%-20x %s\n", $source, $target, $name);
        }
    }
}
close PIPE;
