#!/usr/bin/perl

# do a parameter sweep on xcpu, with timing

use Getopt::Std;
#getopts("m:");
#die "usage: $1 -m msize" unless defined $opt_m;
#$msize = $opt_m;
$msize = 8260;

print "Running with msize = $msize\n";

$path = "~/sxcpu";	# should point to the root of the xcpu source

$xcpubin = "$path/xcpufs/xcpufs";
$rxbin = "$path/utils/xrx";
$bindir = "$path/tests";

@numnodes = qw(8 16 32 64);
@treespawn = qw(2 3 4 5 6 7 8); 
@binaries = qw(b256k b1m b4m b16m);
#@numnodes = qw(3 4 5 7 8 9 15 16 17 63 64 65 127 128 129 255 256 257);
#@treespawn = qw(2 3 5 6 9); 
#@binaries = qw(b256k b1m b4m b16m);

# get the node list
@nn = `cat $ENV{PBS_NODEFILE}`;
@hosts = ();
foreach $n (@nn) {
	chomp $n;
	
	$newh = `host $n | sed 's/.* //'`;
	chomp $newh;
	push(@hosts, $newh);
	print "starting xcpu on $n: \n";
	`ssh $n $xcpubin -s -m $msize`;
}

print join " ", @nodes;
print "\n";

foreach $numnodes (@numnodes) {
	$allnodes = join ",", @hosts[0 .. $numnodes-1];
	foreach $binary (@binaries) {
		foreach $tree (@treespawn) {
			print STDERR "$numnodes $binary $tree "; 
#			print "timing execution on $numnodes nodes with binary $binary and treespawn $tree\n"; 
#			print "nodelist: $allnodes\n";
			`time -p for i in 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 ; do $rxbin -m $msize -n $tree $allnodes $bindir/$binary; done`;
		}
	}
}

print "========now do the same thing with eth_2============\n";
$i = 0;
while($i < $#nodes) {
	$nodes[$i] = $nodes[$i]."eth_2";
	$i++;
}

foreach $numnodes (@numnodes) {
	$allnodes = join ",", @hosts[0 .. $numnodes-1];
	foreach $binary (@binaries) {
		foreach $tree (@treespawn) {
			print STDERR "$numnodes $binary $tree "; 
#			print "timing execution on $numnodes nodes with binary $binary and treespawn $tree\n"; 
#			print "nodelist: $allnodes\n";
			`time -p for i in 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 ; do $rxbin -m $msize -n $tree $allnodes $bindir/$binary; done`;
		}
	}
}
