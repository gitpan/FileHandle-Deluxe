package FileHandle::Deluxe;
use strict;
use IO::Handle;
use IO::Seekable;
use Symbol;
use 5.000;
use vars qw[$VERSION @ISA $CanExec @EXPORT @EXPORT_OK %EXPORT_TAGS];
use Fcntl ':flock';
use Exporter;
@ISA = qw[Exporter IO::Handle IO::Seekable];

# documentation at end of file

# version
$VERSION = '0.90';


# constants
use constant LOCK_NONE => 0;


# imports
@EXPORT_OK = qw[LOCK_SH LOCK_EX LOCK_NB LOCK_UN LOCK_NONE file_lines file_contents];
%EXPORT_TAGS = ('all' => [@EXPORT_OK]);

# module for stringifying the filehandle
use overload '""' => \&stringify, 'fallback' => 1;

# Determine if it appears that this computer can handle forked exec
# Right now we're just detecting if we're in Windows.
# I'd like a more robust detection mechanism
$CanExec = $^O !~ m|win|i;



sub new {
	my $class = shift;
	my $fh = gensym;
	
	${*$fh} = tie *$fh, "${class}::Tie", @_;
	bless $fh, $class;
}

sub seek {
    my $fh = shift;
    ${*$fh}->SEEK( @_ );
}

sub tell {
    my $fh = shift;
    ${*$fh}->TELL( @_ );
}

sub flock {
	my $fh = shift;
	return ${*$fh}->FLOCK(@_);
}

sub write {
	my $fh = shift;
	${*$fh}->WRITE(@_);
}


# returns the path of the file being read/written
sub stringify {
	my $fh = shift;
	return ${*$fh}->{'path'};
}

# returns the contents of the file
sub contents {
	my $fh = shift;
	return ${*$fh}->contents(@_);
}

# returns the lines in the file (chomped) as an array
sub lines {
	my $fh = shift;
	return ${*$fh}->lines(@_);
}


#-------------------------------------------------------------
# non-OO functions
# 
sub file_lines {return FileHandle::Deluxe->new(shift, @_)->lines(@_)}
sub file_contents {return FileHandle::Deluxe->new(shift, @_)->contents(@_)}
# 
# non-OO functions
#-------------------------------------------------------------



#########################################################################################
# FileHandle::Deluxe::Tie
# 
package FileHandle::Deluxe::Tie;
use strict;
use IO::Seekable;
use FileHandle;
use Fcntl ':flock';
use File::Spec::Functions ':ALL';
use Carp 'croak';
use 5.000;
use vars qw[$taint_mode];

# TESTING
# use Dev::ShowStuff ':all';

#---------------------------------------------------------------------
# TIEHANDLE
# 
sub TIEHANDLE {
	my ($class, $path, %opts) = @_;
	my $self = bless({}, $class);
	
	# options may not be tainted
	if (is_tainted(%opts))
		{croak 'tainted options'}
	
	# trim path
	$path =~ s|^\s+||s;
	$path =~ s|\s+$||s;
	
	# must either be in taint mode, or programmer must have
	# agreed to operate outside of taint mode
	unless ($opts{'allow_insecure_code'} || in_taint_mode())
		{no_taint()}
	
	# if there is file open notation, die if it's not allowed
	if (
		(! $opts{'traditional_open_notation'}) and
		($path =~ m/[\>\<\+\|]/s)
		)
		{bad_notation($self, $path)}
	
	# if auto_croak is set to false, then default
	# lazy open to false also
	if (
		(defined $opts{'auto_croak'}) and 
		(! $opts{'auto_croak'}) and 
		(! defined $opts{'lazy_open'})
		)
		{$opts{'lazy_open'} = 0}
	
	# properties
	%{$self} = (
		auto_croak=>1,
		auto_close=>1,
		lazy_open=>1,
		plain_path=>1,
		read => '',
		write => '',
		append => '',
		pipe_to => '',
		pipe_from => '',
		%opts
	);
	
	# if this isn't a "plain path"
	if (
		(! $self->{'traditional_open_notation'}) and 
		$self->{'plain_path'} and
		is_tainted($path) and
		($path !~ m/^(\.\/|\.[a-z0-9 _]|[a-z0-9 _]+|\/)+$/gis)
		) {
		croak 
			'Path may consist only of single dots, alphanumerics, spaces, underscores, and ' . 
			'slashes. See plain_path in documentation for details';
		}
	
	# ensure that these options have the right characters
	$self->{'append'} &&= '>';
	$self->{'append'} and (! $self->{'write'}) and $self->{'write'} = 1;
	$self->{'write'} &&= '>';
	$self->{'write'} or $self->{'read'} = '<';
	$self->{'read'} &&= '<';
	$self->{'pipe_to'} &&= '|-';
	$self->{'pipe_from'} &&= '-|';
	
	# path
	$self->{'path'} = $path;
	
	# if we should open immediately
	unless ($self->{'lazy_open'})
		{$self->get_fh or return undef}
	
	# return
	return $self;
}
# 
# TIEHANDLE
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# called_class (for errors)
# 
sub called_class {
	my ($self) = @_;
	my $class = ref($self);
	$class =~ s|::Tie$||;
	return $class;
}
# 
# called_class
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# get_fh
# 
# get the real filehandle
# 
sub get_fh {
	my ($self) = @_;
	my $open_path = $self->{'path'};
	
	# if already done
	if ($self->{'read_done'})
		{return undef}
	
	# if we already have the file handle, just return it
	$self->{'real_fh'} and return $self->{'real_fh'};
	
	# traditional open notation
	if ($self->{'traditional_open_notation'}) {
		$self->{'real_fh'} = FileHandle->new($self->{'path'});
		
		# if failure
		if (! $self->{'real_fh'}) {
			if ($self->{'auto_croak'})
				{croak "cannot open \"$self->{'path'}\": $!"}
			return undef;
		}
	}
	
	# piping from a program
	elsif ($self->{'pipe_from'} || $self->{'pipe_to'})
		{$self->safe_pipe}
		
	#-----------------------------------------------------------------------
	# reading/writing a regular file
	# 
	else {
		
		#-------------------------------------------------
		# determine if the requested file is in a safe dir
		# 
		# The rule: the path must start with one of the safe dir paths,
		# AND may not contain any backtracks.
		# 
		my $path = $self->{'path'};
		my (@files, @dirs, @trees, $lock);
		my $dirdel = canonpath(rootdir());
		my $dirdelre = quotemeta($dirdel);
		
		# alias safe_dirs to safe_dir and safe_trees to safe_tree
		exists($self->{'safe_files'}) and $self->{'safe_file'} = delete $self->{'safe_files'};
		exists($self->{'safe_dirs'}) and $self->{'safe_dir'} = delete $self->{'safe_dirs'};
		exists($self->{'safe_trees'}) and $self->{'safe_tree'} = delete $self->{'safe_trees'};
		
		# normalize path
		set_canon_path($dirdel, $dirdelre, $path);
		
		# build array of safe directories
		@files = resolve_arr($self->{'safe_file'});
		@dirs = resolve_arr($self->{'safe_dir'});
		@trees = resolve_arr($self->{'safe_tree'});
		
		# none of the safeties can be tainted
		if (is_tainted(@files, @dirs, @trees))
			{croak 'safe_files, safe_dirs, and safe_trees may not contain tainted data'}
		
		# if there are settings for safe files, dirs, and trees
		if (@files || @dirs || @trees) {
			# normalize paths
			set_canon_path($dirdel, $dirdelre, @files, @dirs, @trees);
			grep {s|($dirdelre)*$|$dirdel|} @dirs, @trees;
			
			# safe_files
			if (@files &~ grep {$_ eq $path} @files)
				{croak 'File must be one of the following: ', join(', ', @files)}
			
			# safe_dir
			if (@dirs) {
				# build regex of all dirs
				my $regex = join('|', map {quotemeta} @dirs);
				
				# evaluate path against regex, including no further directory backtracking
				unless (
					$path =~ s/^$regex//is and 
					$path !~ m/$dirdelre/is and 
					desc_only($path)
					)
					{croak "path ($path) must be within one of the following directories: ", join(', ', @dirs)}
			}
			
			# safe_tree
			if (@trees) {
				# build regex of all dirs
				my $regex = join('|', map {quotemeta} @trees);
				
				# evaluate path against regex, including no further directory backtracking
				unless (
					$path =~ s/^$regex//is and 
					desc_only($path)
					)
					{croak "path ($path) must be within one of the following directory trees: ", join(', ', @trees)}
			}
			
			# if we get this far in this block, the path is considered safe
			# WARNING: do not copy and use the following code unless you
			# really know what you're doing.  As a general rule, untainting
			# an entire string is a Bad Idea.  I do it here because the 
			# business rules of this module state that if the given
			# path matches the safe_files, safe_dirs, and safe_trees
			# rules, then the path should be untainted.
			$open_path =~ m|(.*)|;
			$open_path = $1;
		}
		# 
		# determine if the requested file is in a safe dir
		#-------------------------------------------------
		
		
		# refuse to open if tainted
		if (is_tainted($open_path))
			{croak "cannot open file using tainted path: $open_path"}
		
		# open file
		$self->{'real_fh'} = 
			FileHandle->new("$self->{'write'}$self->{'append'}$self->{'read'}$open_path");
		
		# if failure
		if (! $self->{'real_fh'}) {
			if ($self->{'auto_croak'})
				{croak "cannot open \"$self->{'path'}\": $!"}
			return undef;
		}
		
		# determine lock style
		if (defined $self->{'lock'})
			{$lock = $self->{'lock'}}
		else
			{$lock = $self->{'write'} ? LOCK_EX : LOCK_SH}
		
		# get lock
		if ($lock) {
			unless (flock ($self->{'real_fh'}, $lock))
				{$self->{'auto_croak'} and croak 'unable to get file lock'}
		}
		
	}
	# 
	# reading/writing a regular file
	#-----------------------------------------------------------------------
	
	return $self->{'real_fh'};
}
# 
# get_fh
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# set_canon_path
# 
sub set_canon_path {
	my $del = shift;
	my $delre = shift;
	
	foreach my $path (@_) {
		$path = canonpath($path);
		length($path) or croak 'cannot use empty path or directory';
		
		# if just . or ./
		if ($path =~ m|^\.$delre?$|is)
			{$path = ".$del"}
		
		# else if not full path
		elsif ($path !~ m/^($delre|\.)/is)
			{$path = ".$del$path"}
	}
}
# 
# set_canon_path
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# resolve_arr
# 
sub resolve_arr {
	ref($_[0]) and return @{$_[0]};
	return grep {defined} @_;
}
# 
# resolve_arr
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# desc_only
# 
# return true if the given path is free of backtracking
# 
sub desc_only {
	return $_[0] eq join('', no_upwards(map {canonpath $_} splitpath($_[0])));
}
# 
# desc_only
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# safe_pipe
# 
sub safe_pipe {
	my ($self) = @_;
	my ($pipe, $fh);
	my @args = resolve_arr($self->{'args'});
	
	# refuse to work with tainted program and arguments
	if ( (! $self->{'allow_insecure_program_arguments'}) && is_tainted($self->{'path'}, @args))
		{croak 'cannot execute program using tainted program path and/or arguments'}
	
	# open file handle using forked exec method
	if ($FileHandle::Deluxe::CanExec)
		{$fh = FileHandle->new("self->{'pipe_to'}self->{'pipe_from'}") || exec($self->{'path'})}
	
	# else use more traditional shell method if allowed
	elsif($self->{'allow_shell_execute'}) {
		my $cmd = $self->{'path'};
		@args and $cmd .= ' ' . join(' ', @args);
		
		$self->{'pipe_to'} &&= '| ';
		$self->{'pipe_from'} &&= ' |';
		
		$cmd = "$self->{'pipe_to'}$cmd$self->{'pipe_from'}";
		$fh = FileHandle->new($cmd);
	}
	
	# if we didn't get a file handle
	unless ($fh || (! $self->{'auto_croak'}) )
		{croak "Cannot open $self->{'path'}: $!"}
	
	# store filehandle
	$self->{'real_fh'} = $fh;
}
# 
# safe_pipe
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# taint functions
#
sub is_tainted {
	my ($junk);
	return ! eval
		{
		$junk=join('', @_), kill 0;
		1;
		};
}

sub in_taint_mode {
	unless (defined $taint_mode) {
		my ($path) = <.>;
		$taint_mode = is_tainted($path);
	}
	
	return $taint_mode;
}
#
# taint functions
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# eof_close
# 
# Closes the file handle if past the EOF
# Only does so for read-only files.
# Does not do so if $self->{'auto_close'} is false.
# 
sub eof_close {
	my ($self) = @_;
	$self->{'auto_close'} or return;
	($self->{'read'} &~ $self->{'write'}) or return;
	eof($self->get_fh) or return;
	$self->{'read_done'} = 1;
	delete $self->{'real_fh'};
}
# 
# eof_close
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# contents
# 
sub contents {
	my ($self, %opts) = @_;
	my ($fh);
	
	# reset everything
	delete $self->{'real_fh'};
	delete $self->{'read_done'};
	
	$fh = $self->get_fh or return undef;
	
	# array context
	if (wantarray) {
		# get the lines
		my @rv = <$fh>;
		
		# chomp the lines if necessary
		if ($opts{'auto_chomp'})
			{grep {chomp} @rv}
		
		return @rv;
	}
	
	# return in scalar context
	return join('', <$fh>);
}	
# 
# contents
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# lines
# 
sub lines {
	my $self = shift;
	my @rv = $self->contents(auto_chomp=>1, @_);
	return @rv;
}
# 
# lines
#---------------------------------------------------------------------


sub READLINE {
	my ($self) = @_;
	my $fh = $self->get_fh or return undef;
	
	# if array
	if (wantarray) {
		my @rv = <$fh>;
		$self->{'auto_chomp'} and grep {chomp} @rv;
		$self->eof_close;
		return @rv;
	}
	
	# else scalar context
	else {
		my $rv = <$fh>;
		$self->eof_close;
		$self->{'auto_chomp'} and return FileHandle::Deluxe::FileLine->new($rv);
		return $rv;
	}
}


sub READ {
	my $self = shift;
	read($self->get_fh, $_[0], $_[1]);
	$self->eof_close;
}


sub EOF {
	my ($self) = @_;
	return eof($self->get_fh);
}

sub GETC {
    my $self = shift;
	my ($rv);
	$self->READ($rv, 1);
	return $rv;
}


sub WRITE {
	my ($self, $buf, $len, $offset) = @_;
	$offset ||= 0;
	$self->PRINT(substr($buf, $len, $offset));
	$len;
}



sub PRINT {
	my $self = shift;
	my $fh = $self->get_fh;
	return print $fh @_;
}


sub PRINTF {
	my $self = shift;
	return $self->PRINT(sprintf( shift, @_ ));
}

sub CLOSE {
    my $self = shift;
    untie $self;
    $self;
}

sub SEEK {
	my $self = shift;
	my $fh = $self->get_fh;
	return $fh->seek(@_);
}

sub TELL {
	my $self = shift;
	my $fh = $self->get_fh;
	return $fh->tell(@_);
}

sub FLOCK {
	my $self = shift;
	my $fh = $self->get_fh;
	return $fh->flock(@_);
}

sub BINMODE {
	my $self = shift;
	my $fh = $self->get_fh;
	return binmode($fh);
}


#---------------------------------------------------------------------
# err
# 
sub err_exit {
	my ($msg) = @_;
	$msg =~ s|^\n+||;
	$msg =~ s|\n+$||;
	
	print
		"-- ERROR -----------------------------------------------------\n",
		$msg, "\n",
		"--------------------------------------------------------------\n";
	
	exit;
}
# 
# err
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# no_taint
# 
sub no_taint {

err_exit (<<'(NOTAINT)');
You are not running Perl in taint mode.  Taint mode is a 
crucial security layer that you should use in all of your Perl 
programs. In particular, you should *never* run web
applications except in taint mode.

To run Perl in taint mode, add a capital T to your bang path:

 #!/usr/local/bin/perl -wT  

You'll probably also want to set $ENV{'PATH'} to an empty 
string:

 $ENV{'PATH'} = '';

If you are sure that you want to run Perl without tainting, 
you can use FileHandle::Deluxe by adding the 
allow_insecure_code option to your call to new:

 $fh = FileHandle::Deluxe->new($path, allow_insecure_code=>1);
(NOTAINT)

}
# 
# no_taint
#---------------------------------------------------------------------


#---------------------------------------------------------------------
# bad_notation
# 
sub bad_notation {

my ($fh, $path) = @_;

err_exit (<<"(BADNOTATION)");
File path contains meta-characters for filehandle opening: 

 $path

Although traditional Perl allows those characters in FileHandle openings, 
they have a history of creating security problems.  It is highly advised 
that you use the read, write, append, pipe_to, and pipe_from options 
instead.  For example:

 my \$fh = @{ [ $fh->called_class ] }->new(\$path, write=>1);

If you must use the traditional open meta-characters, then you
may indicate the willingness to do so with the 
traditional_open_notation option:

 my \$fh = @{ [ $fh->called_class ] }->new(\$path, traditional_open_notation=>1);
(BADNOTATION)

}
# 
# bad_notation
#---------------------------------------------------------------------



# 
# FileHandle::Deluxe::Tie
#########################################################################################



#########################################################################################
# FileHandle::Deluxe::FileLine
# 
package FileHandle::Deluxe::FileLine;
use strict;
use overload 
	'""' => \&stringify, 
	'bool'=>\&boolify,
	'fallback' => 1;

sub new {
	my ($class, $txt) = @_;
	chomp $txt;
	return bless({'txt'=>$txt}, $class);
}

sub stringify {return $_[0]->{'txt'}}

sub boolify {
	my ($self) = @_;
	$self->{'first_bool'} and return $self->{'txt'};
	return $self->{'first_bool'} = 1;
}

# 
# FileHandle::Deluxe::FileLine
#########################################################################################


# return true
1;

__END__


=head1 NAME

FileHandle::Deluxe - file handle with a lot of extra features

=head1 SYNOPSIS

	use FileHandle::Deluxe;
	
	# Open for read: Don't bother checking for open success, 
	# that's done automatically.  Don't bother locking either,
	# that's also done automatically.
	$fh = FileHandle::Deluxe->new($path);
	
	# Handle stringifies to the path being read
	print 'reading from ', $fh, "\n";
	
	# Loop through the file handle as usual
	# the handle is lazy: the file isn't actually
	# opened until the first read.
	while (<$fh>) {
		...
	}
	
	# the handle automatically closes when the
	# the last line is read

=head1 INSTALLATION

FileHandle::Deluxe can be installed with the usual routine:

	perl Makefile.PL
	make
	make test
	make install

You can also just copy Deluxe.pm into the FileHandle/ directory of one of your library trees.

=head1 DESCRIPTION

FileHandle::Deluxe works like a regular FileHandle object, with the addition of doing the
routine file handle chores for you.  FileHandle::Deluxe (FD) is targeted at beginning Perl 
users who usually find those tasks intimidating and often elect to skip them rather than learn
how to do them.  FileHandle::Deluxe defaults to a set of best practices for working with 
file handles.

The following sections describe the practices and features implemented by FD.

=head2 Security

FileHandles are the most notorious source of Perl application security holes. 
FD implements a strict set of security rules.  Rather than allowing users
"enough rope to hang themselves", FD forces the user to either program more
securely or explicitly acknowlege that their program uses insecure techniques.
Hopefully most FD users will choose the first option.

For beginners, FD refuses to run unless either Perl is in taint mode or the developer
gives explicit permission for FD to run while not in taint mode. See the documentation
on the allow_insecure_code option below for more details.

FD also dispenses with the traditional notation for indicating if a file should be opened
for reading, writing, etc. For example, the argument "> mydata.txt" would be prohibited.
Instead, to indicate opening a file for writing, the command for a new file handle would
use the C<write> option:

 $fh = FileHandle::Deluxe->new($path, write=>1);

FD refuses to open any file using a tainted path.  (Regular file handles will open files for 
read using tainted paths.)  Users, however, frequently find the task of properly untainting
paths more than they want to deal with, so FD helps out.  The user may indicate that certain 
files, directories, or entire directory trees are "safe".  Tainted data paths may be used to
open files within safe locations.   See the sections for safe_files, safe_dirs, and safe_trees
below for more details.

FD also addresses security issues with executable files.  When an FD file handle is opened for
piping to and from an executable, FD automatically uses the more secure exec method for opening
the file handles.  The exec method opens the executables directly, instead of spawning an 
intermediate shell, thereby bypassing shell hacks. See the sections for pipe_to and pipe_from 
below for more details.

=head2 File Locking

File locking is a file handle housekeeping nuisance that even experienced Perl programmers often
overlook.  FD takes care of file locking chores for you.  Files that are opened as read only
get a shared lock.  Files that are opened as writable get an exclusive lock.  See the section on
file locks below for more details.

=head2 Resource Conservation

FD file handles are "lazy"... they do not open the files until they are actually used.  Furthermore, for read-only
files, the file handles are closed once the last line of the file is read.  By using these conservation features, 
a function can return a large number of FD objects (perhaps representing all the files in a directory) without 
using up limited system file handles.  See the section on the lazy and auto_close options below for more details.

=head2 Convenience

FD simplifies many tasks associated with working with files. For beginners, FD objects stringify to the file paths, so a function can return a series of FD objects that can be easily used to output file names.  FD handles also provide the ability to quickly slurp in the entire contents of a file either as an array of pre-chomped lines or as a single string.  See the lines and contents methods below, and also the non-OO functions file_lines and file_contents.

Speaking of chomping, FD handles can also be set to automatically chomp lines as you pull them from the file.  See the auto_chomp option for more details. 

=head1 METHODS

=head2 FileHandle->new($path);

The C<new> method creates a new FileHandle::Deluxe object.  The first and only required argument is a file path.  If there are no further arguments, the file is opened for reading, the file gets a shared lock, and the entire program croaks if the file cannot be opened.  The path may not be tainted unless the safe_files, safe_dirs, and/or safe_trees options are used (see option list below for more details). 

The following optional arguments may be passed to C<new>.  None of these arguments may be tainted.

=over 4

=item append

Open the file for appending... that is, add to the file without deleting what is already there.
The file does not need to already exist.  If this option is set, then the C<write>
option is also assumed to be true.

Example:

 $fh = FileHandle::Deluxe->new('data.txt', append=>1);


=item allow_insecure_code

This option must be set to true if you want to use FileHandle::Deluxe while not running in taint mode.
It is I<highly recommended> that you always run Perl in taint mode until you are clear on when it is ok
not to use tainting.  In particular, you should I<always> use taint mode for web applications, regardless
of how safe you think it is.  If you are making the mistake of developing a web application 
without using tainting, consider the words of Randal L. Schwartz, one of the world's foremost experts
on Perl: "*All* of my Web scripts run with taintchecks on.  Cuz I make mistakes sometimes.  Fancy that. :-)"

To run Perl in taint mode, add a capital T to your bang path:

 #!/usr/local/bin/perl -wT  

You'll probably also want to set $ENV{'PATH'} to an empty string at the top of your script:

 $ENV{'PATH'} = '';

If you are sure that you want to run Perl without tainting, you can use FileHandle::Deluxe by adding the 
allow_insecure_code option to your call to new:

 $fh = FileHandle::Deluxe->new($path, allow_insecure_code=>1);

=item allow_insecure_program_arguments

FileHandle::Deluxe uses the piped exec method for opening executables.  That means that, among things, 
tainted arguments can be passed to the executable.  Passing tainted arguments to an external program 
won't cause any security problems in your Perl script itself, but it might cause security holes in the 
external program itself, so FileHandle::Deluxe does not allow it by default.

If you are sure you want to allow tainted arguments to be passed, set allow_insecure_program_arguments to true:

 $fh = FileHandle::Deluxe->new(
     $path, 
     pipe_to=>1,
     args=>[@arguments],
     allow_insecure_program_arguments=>1,
     );

If FileHandle::Deluxe uses the shell method for opening an executable (see allow_shell_execute below), and if tainting is on, then allow_insecure_program_arguments makes no difference, the arguments may not be tainted.

=item allow_shell_execute

FileHandle::Deluxe uses the piped exec method for opening executables (which is much more secure) if the operating system appears to support it.  (The current test for supporting piped exec is if $^O contains the string "Win" .. i.e. it's a Windows machine... which is perhaps not the most robust test.  Suggestions are welcome.)  If it appears that the OS does NOT support piped execs, then it will open the executable using a shell, but I<only> if the allow_shell_execute option is set to true, like this:

 $fh = FileHandle::Deluxe->new(
     $path, 
     pipe_to=>1,
     args=>[@arguments],
     allow_shell_execute=>1,
     );

If FileHandle::Deluxe uses the shell method for opening an executable, and if tainting is on, then program arguments may not be tainted.

=item args

Arguments to pass to an external executable.  For example, the following code sends four arguments to sendmail:

 $fh = FileHandle::Deluxe->new(
     $sendmail, 
     pipe_to=>1,
     args=>['-t', '-f', 'error@idocs.com', 'miko@idocs.com'],
     );

=item auto_close

By default, FileHandle::Deluxe closes read-only files when the last line is read.  This conserves system file handles 
and frees up locks for other objects that may be using the same file.  If you want the handle to keep the file open after the last line is read, set C<auto_close> to false:

 $fh = FileHandle::Deluxe->new($path, auto_close=>0);

=item auto_chomp

The C<auto_chomp> option (which is not on by default) tells the file handle to remove trailing end-of-line characters each time a line is read from the file.  So, for example, the following code reads all the lines from the file, removing end-of-line characters form each line:

 $fh = FileHandle::Deluxe->new($path, auto_chomp=>1);
 
 while (<$fh>) {
   if ($_ eq 'Fred'){...}
   elsif ($_ eq 'Barney'){...}
 }

Contrary to what you might expect, empty lines and lines consisting of the zero character ("0"), do I<not> fail the initial test in the while loop.  That's because in C<auto_chomp> mode, the returned "line" is really an object that boolifies to true the first time it is tested.  All subsequent boolean tests are based on the content of the line.  The object always stringifies to the text of the line in the file, so use it like a regular string.

=item auto_croak

By default, FileHandle::Deluxe croaks if it is unable to open the file.  If you would prefer to do your own croaking, set C<auto_croak> to true.

 $fh = FileHandle::Deluxe->new($path, auto_croak=>1);

If C<auto_croak> is set to false then C<lazy_open> defaults to false as well, meaning that the open attempt occurs when the FileHandle::Deluxe object is created.

=item lazy_open

By default, FileHandle::Deluxe does not open the file until a read or write call is made to the file handle (this does not
apply to handles for executables).  If you want the file to open when C<new> is called, set C<lazy_open> to false:

 $fh = FileHandle::Deluxe->new($path, lazy_open=>1);

C<lazy_open> defaults to false if you set C<auto_croak> to false.

=item lock

By default, FileHandle::Deluxe gets a shared lock for read-only file handles, and an exclusive lock for 
write or read/write handles.  If you want to get a different type of lock, or no lock at all, set the 
C<lock> option.  For no lock, set C<lock> to 0:

 $fh = FileHandle::Deluxe->new($path, lock=>0);

For any other lock, use LOCK_SH (shared lock), LOCK_EX (exclusive lock), and LOCK_NB (do not wait for lock).  To use these constants, you must add the ':all' option to your use FileHandle::Deluxe call, like this:

 use FileHandle::Deluxe ':all';

=item pipe_from, pipe_to

C<pipe_from> and C<pipe_to> indicate to pipe to or from an executable file.  For example, the following command indicates to open a handle for piping to Sendmail (where $sendmail is the path to the Sendmail executable):

 $fh = FileHandle::Deluxe->new($sendmail, pipe_to=>1);

Any arguments you want passed to the executable should be sent with the C<args> option as an array reference:

 $fh = FileHandle::Deluxe->new(
     $sendmail, 
     pipe_to=>1,
     args=>['-t', '-f', 'error@idocs.com', 'miko@idocs.com'],
     );

=item plain_path

C<plain_path>, which is true by default, indicates that if the given file is tainted, it may only consist of a "plain" file path characters, that is, single dots, alphanumerics, spaces, underscores, and slashes.  Doubles dots, ampersands, pipes, and other fancy characters are prohibited.

C<plain_path> is the single best security layer FileHandle::Deluxe gives you.  It is highly recommended that you do not disable C<plain_path>.

=item read

Indicates that the file should be open for reading.  If none of C<write>, C<append>, C<pipe_to>, or C<pipe_from> are
sent than C<read> defaults to true.

=item safe_files, safe_dirs, safe_trees

These options indicate "safe" locations for the file.  The file path must be within one of the locations for each 
of these options that is sent, or it will not be opened.  If the file path is tainted, but is within one of these locations, then it will be opened.

C<safe_files> gives a list of complete file paths.  The path for opening must be one of the given paths.  For example, the following command indicates that FileHandle::Deluxe may open data.txt, names.txt, or adds.txt:

 $fh = FileHandle::Deluxe->new(
     $path, 
     safe_files=>['data.txt', 'names.txt', 'adds.txt'],
     );

C<safe_dirs> gives a list of directories, one of which the file must be in.  The file must be directly within the directory, not nested deeper in the directory tree (see C<safe_trees> below for that).  For example, the following command indicates that the file must be directly within ./data/, ./names/, or ./adds/:

 $fh = FileHandle::Deluxe->new(
     $path, 
     safe_dirs=>['./data/', './names/', './adds/'],
     );

C<safe_trees> also gives a list of directories, but the file may be anywhere nested within one of the directories, not necessarily directly within it.  So, for example, if one of the given directories was ./adds/:

 $fh = FileHandle::Deluxe->new(
     $path, 
     safe_trees=>['./data/', './names/', './adds/'],
     );

then ./adds/joined/data.txt, ./adds/joined/quit/data.txt, as well as ./adds/data.txt would all be accepted.

=item traditional_open_notation

C<traditional_open_notation>, which is false by default, indicates that FileHandle::Deluxe should open the file 
using traditional Perl file handle opening notation.  For example, traditionally a handle for writing to a file 
would be opened like this (notice the > at the beginning of the path string):

 $fh = FileHandle->new('> data.txt') or die $!;

The problem with that technique is that it makes it easier for careless programming to open security holes.  If the file path is carelessly untainted then unintended commands can be run through the shell.  FileHandle::Deluxe prohibits shell meta-characters unless you explictly choose to use them with 
C<traditional_open_notation>:

 $fh = FileHandle->new('> data.txt', traditional_open_notation=>1);

Avoid using C<traditional_open_notation>.  Use the C<read>, C<write>, C<append>, C<pipe_to>, and C<pipe_from> options instead.  C<traditional_open_notation> also negates the C<plain_path> option.

=item write

C<write> indicates that the file should be opened for writing:

 $fh = FileHandle->new('data.txt', write=>1);

=head2 contents

The C<contents> method returns the entire contents of the file.  In array context it returns each line as an individual element in the array.  It scalar context it returns the file as a single string.  So, for example, the following 
command outputs the entire file:

 print $fh->contents;

=head2 lines

The C<contents> method returns the entire contents of the file as an array.  Each line is an individual element in the array.  All lines are chomped.  For example, the following code assigns the lines to an array:

 @names = $fh->lines;

=head2 file_contents, file_lines

C<file_contents> and C<file_lines> are static (i.e. no object required) equivalents for slurping in the entire contents of a file.  These commands can be imported by adding the ':all' option to your use FileHandle::Deluxe call, like this:

 use FileHandle::Deluxe ':all';

Each of these commands takes the file path as the first argument:

 print file_contents('data.txt');
 @arr file_lines('data.txt');

=head1 MISC INTERESTING STUFF

FileHandle::Deluxe objects stringify to the path for the file they open.  That means you can use the object as a string if you want to know the path:

	print 'reading from ', $fh, "\n";

=back 4

=head1 TERMS AND CONDITIONS

Copyright (c) 2001-2002 by Miko O'Sullivan.  All rights reserved.  This program is 
free software; you can redistribute it and/or modify it under the same terms 
as Perl itself. This software comes with B<NO WARRANTY> of any kind.

=head1 AUTHOR

Miko O'Sullivan
F<miko@idocs.com>


=head1 VERSION

=over

=item Version 0.90    Aug 19, 2002

Initial release


=back


=begin CPAN

-------------------------------------------------------------------
Version 0.90

registered:  Aug 19, 2002
uploaded:    
appeared:    
announced:   


=end CPAN


=cut
