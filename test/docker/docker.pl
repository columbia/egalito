#!/usr/bin/perl

sub image_name($%);
sub has_build($%);
sub run_build(%);
sub run_build_cross(%);
sub run_command($%);
sub run_make(%);
sub run_tests(%);
sub main();

my $CURRENT_ARCH = `uname -m`;
chomp $CURRENT_ARCH;
main();

sub print_usage() {
    print <<EOF
Usage: $0 [--arch (x86_64|aarch64|arm)] command
Commands:
    help        print this help message
    build       set up docker images
    shell       enter a shell in the docker image
    make        builds egalito (with cross compiler if --cross)
    test        executes ./runner inside docker image
EOF
    ;
    exit(0);
}

sub main() {
    my %setting = (
        'arch'  => $CURRENT_ARCH,
        'cross' => '',
        'root'  => '../../',
        'parallel'  => '-j 4'
    );

    print_usage() if @ARGV == 0;

    for(my $a = 0; $a < @ARGV; $a ++) {
        my $arg = $ARGV[$a];

        if($arg eq '--arch') {
            $setting{'arch'} = $ARGV[++$a];
        }
        elsif($arg eq '--cross') {
            $setting{'cross'} = 'x86_64';
        }
        elsif($arg eq '--no-cross') {
            $setting{'cross'} = '';
        }
        elsif($arg eq '--root') {
            $setting{'root'} = $ARGV[++$a];
            $setting{'root'} .= '/' if($setting{'root'} !~ m|/$|);
        }
        elsif($arg eq '-j') {
            $setting{'parallel'} = '-j ' . $ARGV[++$a];
        }
        else {  # must be a command
            if($arg eq 'help') {
                print_usage();
            }
            elsif($arg eq 'build') {
                run_build(%setting);
            }
            elsif($arg eq 'shell') {
                run_command('/bin/bash', %setting);
            }
            elsif($arg eq 'make') {
                run_make(%setting);
            }
            elsif($arg eq 'test') {
                run_tests(%setting);
            }
            else {
                print "Warning: unknown command '$arg'\n";
            }
        }
    }

    if($setting{'cross'} ne '' && $setting{'arch'} eq $CURRENT_ARCH) {
        die "Error: with --cross, please specify --arch <arch>\n";
    }

}

sub image_name($%) {
    my $crossmode = shift @_;
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $cross = $setting{'cross'};

    if($cross eq '' || $crossmode == 0) {
        return "egalito/$arch";
    }
    else {
        return "egalito/$cross-$arch";
    }
}

sub has_build($%) {
    my $crossmode = shift @_;
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $image_name = image_name($crossmode, %setting);

    return (`docker images | grep $image_name` ne '') ? 1 : 0;
}

sub run_build(%) {
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $droot = $setting{'root'} . 'test/docker';
    $setting{'cross'} = '';
    my $image_name = image_name(0, %setting);

    print "building docker image $image_name...\n";

    # extract qemu-user-static from different image
    if($arch ne $CURRENT_ARCH) {
        system("docker run --rm --privileged multiarch/qemu-user-static:register --reset");
        system("docker create --name register hypriot/qemu-register");
        system("docker cp register:qemu-$arch $droot/qemu-$arch-static");
    }

    # build the egalito docker image
    my $ret = system("docker build -t $image_name -f $droot/Dockerfile_$arch $droot");
    print "docker build exit code: " . ($ret >> 8) . "\n";
}

sub run_build_cross(%) {
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $droot = $setting{'root'} . 'test/docker';
    my $image_name = image_name(1, %setting);

    run_build(%setting) unless has_build(0, %setting);

    system("docker build -t $image_name -f $droot/Dockerfile_$cross-$arch $droot");
}

sub run_command($%) {
    my $cmd = shift @_;
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $root = $setting{'root'};
    my $cross = $setting{'cross'};
    my $image_name = image_name(1, %setting);

    run_build(%setting) unless has_build(0, %setting);
    if($cross ne '') {
        run_build_cross(%setting) unless has_build(1, %setting);
    }

    system("docker run -it -e LOCAL_USER_ID=\$(id -u) "
        . "-v \$(readlink -f $root):/egalito $image_name $cmd");
}

sub run_make(%) {
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $cross = $setting{'cross'};
    my $parallel = $setting{'parallel'};

    if($cross ne '') {
        my $cmd = "cd /egalito && USE_CONFIG=travis_${arch}_config.mk make src";
        run_command("/bin/bash -c '$cmd'", %setting);
    }
    else {
        my $cmd = "cd /egalito && make $parallel";
        run_command("/bin/bash -c '$cmd'", %setting);
    }
}

sub run_tests(%) {
    my %setting = @_;
    my $arch = $setting{'arch'};
    my $jobs = $setting{'jobs'};
    my $parallel = $setting{'parallel'};
    $setting{'cross'} = '';

    my $cmd = "cd /egalito/test && ./runner";
    run_command("/bin/bash -c '$cmd'", %setting);
}
