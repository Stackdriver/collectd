# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build

# Include any dependencies generated for this target.
include src/CMakeFiles/yajl_s.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/yajl_s.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/yajl_s.dir/flags.make

src/CMakeFiles/yajl_s.dir/yajl.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl.c.o: ../src/yajl.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl.c

src/CMakeFiles/yajl_s.dir/yajl.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl.c > CMakeFiles/yajl_s.dir/yajl.c.i

src/CMakeFiles/yajl_s.dir/yajl.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl.c -o CMakeFiles/yajl_s.dir/yajl.c.s

src/CMakeFiles/yajl_s.dir/yajl.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl.c.o

src/CMakeFiles/yajl_s.dir/yajl_lex.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_lex.c.o: ../src/yajl_lex.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_lex.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_lex.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_lex.c

src/CMakeFiles/yajl_s.dir/yajl_lex.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_lex.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_lex.c > CMakeFiles/yajl_s.dir/yajl_lex.c.i

src/CMakeFiles/yajl_s.dir/yajl_lex.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_lex.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_lex.c -o CMakeFiles/yajl_s.dir/yajl_lex.c.s

src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_lex.c.o

src/CMakeFiles/yajl_s.dir/yajl_parser.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_parser.c.o: ../src/yajl_parser.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_3)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_parser.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_parser.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_parser.c

src/CMakeFiles/yajl_s.dir/yajl_parser.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_parser.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_parser.c > CMakeFiles/yajl_s.dir/yajl_parser.c.i

src/CMakeFiles/yajl_s.dir/yajl_parser.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_parser.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_parser.c -o CMakeFiles/yajl_s.dir/yajl_parser.c.s

src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_parser.c.o

src/CMakeFiles/yajl_s.dir/yajl_buf.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_buf.c.o: ../src/yajl_buf.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_4)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_buf.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_buf.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_buf.c

src/CMakeFiles/yajl_s.dir/yajl_buf.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_buf.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_buf.c > CMakeFiles/yajl_s.dir/yajl_buf.c.i

src/CMakeFiles/yajl_s.dir/yajl_buf.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_buf.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_buf.c -o CMakeFiles/yajl_s.dir/yajl_buf.c.s

src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_buf.c.o

src/CMakeFiles/yajl_s.dir/yajl_encode.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_encode.c.o: ../src/yajl_encode.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_5)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_encode.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_encode.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_encode.c

src/CMakeFiles/yajl_s.dir/yajl_encode.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_encode.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_encode.c > CMakeFiles/yajl_s.dir/yajl_encode.c.i

src/CMakeFiles/yajl_s.dir/yajl_encode.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_encode.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_encode.c -o CMakeFiles/yajl_s.dir/yajl_encode.c.s

src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_encode.c.o

src/CMakeFiles/yajl_s.dir/yajl_gen.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_gen.c.o: ../src/yajl_gen.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_6)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_gen.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_gen.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_gen.c

src/CMakeFiles/yajl_s.dir/yajl_gen.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_gen.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_gen.c > CMakeFiles/yajl_s.dir/yajl_gen.c.i

src/CMakeFiles/yajl_s.dir/yajl_gen.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_gen.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_gen.c -o CMakeFiles/yajl_s.dir/yajl_gen.c.s

src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_gen.c.o

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o: ../src/yajl_alloc.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_7)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_alloc.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_alloc.c

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_alloc.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_alloc.c > CMakeFiles/yajl_s.dir/yajl_alloc.c.i

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_alloc.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_alloc.c -o CMakeFiles/yajl_s.dir/yajl_alloc.c.s

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o

src/CMakeFiles/yajl_s.dir/yajl_tree.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_tree.c.o: ../src/yajl_tree.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_8)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_tree.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_tree.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_tree.c

src/CMakeFiles/yajl_s.dir/yajl_tree.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_tree.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_tree.c > CMakeFiles/yajl_s.dir/yajl_tree.c.i

src/CMakeFiles/yajl_s.dir/yajl_tree.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_tree.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_tree.c -o CMakeFiles/yajl_s.dir/yajl_tree.c.s

src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_tree.c.o

src/CMakeFiles/yajl_s.dir/yajl_version.c.o: src/CMakeFiles/yajl_s.dir/flags.make
src/CMakeFiles/yajl_s.dir/yajl_version.c.o: ../src/yajl_version.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_9)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object src/CMakeFiles/yajl_s.dir/yajl_version.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/yajl_s.dir/yajl_version.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_version.c

src/CMakeFiles/yajl_s.dir/yajl_version.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/yajl_s.dir/yajl_version.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_version.c > CMakeFiles/yajl_s.dir/yajl_version.c.i

src/CMakeFiles/yajl_s.dir/yajl_version.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/yajl_s.dir/yajl_version.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/yajl_version.c -o CMakeFiles/yajl_s.dir/yajl_version.c.s

src/CMakeFiles/yajl_s.dir/yajl_version.c.o.requires:
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_version.c.o.requires

src/CMakeFiles/yajl_s.dir/yajl_version.c.o.provides: src/CMakeFiles/yajl_s.dir/yajl_version.c.o.requires
	$(MAKE) -f src/CMakeFiles/yajl_s.dir/build.make src/CMakeFiles/yajl_s.dir/yajl_version.c.o.provides.build
.PHONY : src/CMakeFiles/yajl_s.dir/yajl_version.c.o.provides

src/CMakeFiles/yajl_s.dir/yajl_version.c.o.provides.build: src/CMakeFiles/yajl_s.dir/yajl_version.c.o

# Object files for target yajl_s
yajl_s_OBJECTS = \
"CMakeFiles/yajl_s.dir/yajl.c.o" \
"CMakeFiles/yajl_s.dir/yajl_lex.c.o" \
"CMakeFiles/yajl_s.dir/yajl_parser.c.o" \
"CMakeFiles/yajl_s.dir/yajl_buf.c.o" \
"CMakeFiles/yajl_s.dir/yajl_encode.c.o" \
"CMakeFiles/yajl_s.dir/yajl_gen.c.o" \
"CMakeFiles/yajl_s.dir/yajl_alloc.c.o" \
"CMakeFiles/yajl_s.dir/yajl_tree.c.o" \
"CMakeFiles/yajl_s.dir/yajl_version.c.o"

# External object files for target yajl_s
yajl_s_EXTERNAL_OBJECTS =

yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_lex.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_parser.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_buf.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_encode.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_gen.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_tree.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/yajl_version.c.o
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/build.make
yajl-2.1.1/lib/libyajl_s.a: src/CMakeFiles/yajl_s.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C static library ../yajl-2.1.1/lib/libyajl_s.a"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && $(CMAKE_COMMAND) -P CMakeFiles/yajl_s.dir/cmake_clean_target.cmake
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/yajl_s.dir/link.txt --verbose=$(VERBOSE)
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/cmake -E copy_if_different /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/api/yajl_parse.h /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src/../yajl-2.1.1/include/yajl
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/cmake -E copy_if_different /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/api/yajl_gen.h /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src/../yajl-2.1.1/include/yajl
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/cmake -E copy_if_different /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/api/yajl_common.h /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src/../yajl-2.1.1/include/yajl
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && /usr/bin/cmake -E copy_if_different /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src/api/yajl_tree.h /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src/../yajl-2.1.1/include/yajl

# Rule to build all files generated by this target.
src/CMakeFiles/yajl_s.dir/build: yajl-2.1.1/lib/libyajl_s.a
.PHONY : src/CMakeFiles/yajl_s.dir/build

src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_lex.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_parser.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_buf.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_encode.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_gen.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_alloc.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_tree.c.o.requires
src/CMakeFiles/yajl_s.dir/requires: src/CMakeFiles/yajl_s.dir/yajl_version.c.o.requires
.PHONY : src/CMakeFiles/yajl_s.dir/requires

src/CMakeFiles/yajl_s.dir/clean:
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src && $(CMAKE_COMMAND) -P CMakeFiles/yajl_s.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/yajl_s.dir/clean

src/CMakeFiles/yajl_s.dir/depend:
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/src /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/src/CMakeFiles/yajl_s.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/yajl_s.dir/depend

