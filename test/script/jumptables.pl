#!/usr/bin/perl
# Compile sources with gcc -fdump-rtl-dfinish
# Then this script will parse the output for jump tables

die "Usage: $0 file1.310r.dfinish ...\n" unless @ARGV > 0;

my %seen = ();
my $function = '';
my $entries = 0;
my $mode = 'outside';
while(my $line = <>) {
    if($mode eq 'outside') {
        if($line =~ /;; Function (\S+)/) {
            $function = $1;
            $seen{$function} ++;
        }
        elsif($line =~ /\(jump_table_data .*/) {
            $mode = 'in-data';
        }
    }
    elsif($mode eq 'in-data') {
        if($line =~ /^\s+\[$/) {
            $mode = 'in-entries';
            $entries = 0;
        }
        elsif($line =~ /^\S/) {
            $mode = 'outside';
            redo;
        }
    }
    elsif($mode eq 'in-entries') {
        if($line =~ /^\s+\]$/) {
            # sometimes multiple versions of the same function will appear.
            # for now, we only print jump tables from the first copy.
            if($seen{$function} == 1) {
                print "jump table in [$function] has $entries entries\n";
            }
            $entries = 0;
            $mode = 'in-data';
        }
        elsif($line =~ /\(label_ref:.*\)$/) {
            $entries ++;
        }
    }
# (jump_table_data 18 17 19 (addr_diff_vec:SI (label_ref:DI 17)
#          [
#             (label_ref:DI 44)
#             (label_ref:DI 40)
#             (label_ref:DI 36)
#             (label_ref:DI 32)
#             (label_ref:DI 28)
#             (label_ref:DI 24)
#             (label_ref:DI 20)
#         ]
#         (const_int 0 [0])
#         (const_int 0 [0])))
}

if($entries > 0) {
    die "Warning: unterminated jump table?";
}

close RTL;
