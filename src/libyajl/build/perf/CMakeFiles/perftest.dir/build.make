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
include perf/CMakeFiles/perftest.dir/depend.make

# Include the progress variables for this target.
include perf/CMakeFiles/perftest.dir/progress.make

# Include the compile flags for this target's objects.
include perf/CMakeFiles/perftest.dir/flags.make

perf/CMakeFiles/perftest.dir/perftest.c.o: perf/CMakeFiles/perftest.dir/flags.make
perf/CMakeFiles/perftest.dir/perftest.c.o: ../perf/perftest.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object perf/CMakeFiles/perftest.dir/perftest.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/perftest.dir/perftest.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/perftest.c

perf/CMakeFiles/perftest.dir/perftest.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/perftest.dir/perftest.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/perftest.c > CMakeFiles/perftest.dir/perftest.c.i

perf/CMakeFiles/perftest.dir/perftest.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/perftest.dir/perftest.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/perftest.c -o CMakeFiles/perftest.dir/perftest.c.s

perf/CMakeFiles/perftest.dir/perftest.c.o.requires:
.PHONY : perf/CMakeFiles/perftest.dir/perftest.c.o.requires

perf/CMakeFiles/perftest.dir/perftest.c.o.provides: perf/CMakeFiles/perftest.dir/perftest.c.o.requires
	$(MAKE) -f perf/CMakeFiles/perftest.dir/build.make perf/CMakeFiles/perftest.dir/perftest.c.o.provides.build
.PHONY : perf/CMakeFiles/perftest.dir/perftest.c.o.provides

perf/CMakeFiles/perftest.dir/perftest.c.o.provides.build: perf/CMakeFiles/perftest.dir/perftest.c.o

perf/CMakeFiles/perftest.dir/documents.c.o: perf/CMakeFiles/perftest.dir/flags.make
perf/CMakeFiles/perftest.dir/documents.c.o: ../perf/documents.c
	$(CMAKE_COMMAND) -E cmake_progress_report /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/CMakeFiles $(CMAKE_PROGRESS_2)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building C object perf/CMakeFiles/perftest.dir/documents.c.o"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -o CMakeFiles/perftest.dir/documents.c.o   -c /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/documents.c

perf/CMakeFiles/perftest.dir/documents.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/perftest.dir/documents.c.i"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -E /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/documents.c > CMakeFiles/perftest.dir/documents.c.i

perf/CMakeFiles/perftest.dir/documents.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/perftest.dir/documents.c.s"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && /usr/bin/gcc  $(C_DEFINES) $(C_FLAGS) -S /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf/documents.c -o CMakeFiles/perftest.dir/documents.c.s

perf/CMakeFiles/perftest.dir/documents.c.o.requires:
.PHONY : perf/CMakeFiles/perftest.dir/documents.c.o.requires

perf/CMakeFiles/perftest.dir/documents.c.o.provides: perf/CMakeFiles/perftest.dir/documents.c.o.requires
	$(MAKE) -f perf/CMakeFiles/perftest.dir/build.make perf/CMakeFiles/perftest.dir/documents.c.o.provides.build
.PHONY : perf/CMakeFiles/perftest.dir/documents.c.o.provides

perf/CMakeFiles/perftest.dir/documents.c.o.provides.build: perf/CMakeFiles/perftest.dir/documents.c.o

# Object files for target perftest
perftest_OBJECTS = \
"CMakeFiles/perftest.dir/perftest.c.o" \
"CMakeFiles/perftest.dir/documents.c.o"

# External object files for target perftest
perftest_EXTERNAL_OBJECTS =

perf/perftest: perf/CMakeFiles/perftest.dir/perftest.c.o
perf/perftest: perf/CMakeFiles/perftest.dir/documents.c.o
perf/perftest: yajl-2.1.1/lib/libyajl_s.a
perf/perftest: perf/CMakeFiles/perftest.dir/build.make
perf/perftest: perf/CMakeFiles/perftest.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking C executable perftest"
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/perftest.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
perf/CMakeFiles/perftest.dir/build: perf/perftest
.PHONY : perf/CMakeFiles/perftest.dir/build

perf/CMakeFiles/perftest.dir/requires: perf/CMakeFiles/perftest.dir/perftest.c.o.requires
perf/CMakeFiles/perftest.dir/requires: perf/CMakeFiles/perftest.dir/documents.c.o.requires
.PHONY : perf/CMakeFiles/perftest.dir/requires

perf/CMakeFiles/perftest.dir/clean:
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf && $(CMAKE_COMMAND) -P CMakeFiles/perftest.dir/cmake_clean.cmake
.PHONY : perf/CMakeFiles/perftest.dir/clean

perf/CMakeFiles/perftest.dir/depend:
	cd /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/perf /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf /usr/local/google/home/zhihuawen/git/collectd-gcm-sd/src/libyajl/build/perf/CMakeFiles/perftest.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : perf/CMakeFiles/perftest.dir/depend

