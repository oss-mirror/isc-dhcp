# Copyright (C) 2014-2015,2017 Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# A list of processes, mainly used by the cleanup functions.

# colors if not outputting to a dumb terminal and stdout is a tty
if test "$TERM" != dumb && { test -t 1; } 2>/dev/null; then \
    red='\033[0;31m'
    red='\e[1;31m'
    green='\e[1;32m'
    blue='\e[1;34m'
    yellow='\e[1;33m'
    clear='\e[m'

    # if echo supports -e, we must use it to set colors
    # (output will be "" if its supported)
    if [ -z "`echo -e`" ]
    then
        dash_e="-e"
    fi
fi;

### Logging functions ###

# Prints error message.
test_lib_error() {
    local s=${1}            # Error message.
    local no_new_line=${2}  # If specified, the message not terminated with
                            # new line.
    printf "ERROR/test_lib: %s" "${s}"
    if [ -z ${no_new_line} ]; then
        printf "%s" "\n"
    fi

}

# Prints info message.
test_lib_info() {
    local s=${1}            # Info message.
    local no_new_line=${2}  # If specified, the message is not terminated with
                            # new line.
    printf "INFO/test_lib: %s" "${s}"
    if [ -z ${no_new_line} ]; then
        printf "%s" "\n"
    fi
}

### Assertions ###

# Assertion that checks if two numbers are equal.
# If numbers are not equal, the mismatched values are presented and the
# detailed error is printed. The detailed error must use the printf
# formatting like this:
#    "Expected that some value 1 %d is equal to some other value %d".
assert_eq() {
    val1=${1}         # Reference value
    val2=${2}         # Tested value
    detailed_err=${3} # Detailed error format string
    # If nothing found, present an error an exit.
    if [ ${val1} -ne ${val2} ]; then
        printf "Assertion failure: ${val1} != ${val2}, for val1=${val1}, val2=${val2}\n"
        printf "${detailed_err}\n" ${val1} ${val2}
        clean_exit 1
    fi
}

# Assertion that checks if two strings are equal.
# If numbers are not equal, the mismatched values are presented and the
# detailed error is printed. The detailed error must use the printf
# formatting like this:
#    "Expected that some value 1 %d is equal to some other value %d".
assert_str_eq() {
    val1=${1}         # Reference value
    val2=${2}         # Tested value
    detailed_err=${3} # Detailed error format string
    # If nothing found, present an error an exit.
    if [ "${val1}" != "${val2}" ]; then
        printf "Assertion failure: ${val1} != ${val2}, for val1=${val1}, val2=${val2}\n"
        printf "${detailed_err}\n" ${val1} ${val2}
        clean_exit 1
    fi
}

# Assertion that checks if one string contains another string.
# If assertion fails, both strings are displayed and the detailed
# error is printed. The detailed error must use the printf formatting
# like this:
#    "Expected some string to contain this string: %s".
assert_string_contains() {
    pattern="${1}"      # Substring or awk pattern
    text="${2}"         # Text to be searched for substring
    detailed_err="${3}" # Detailed error format string
    # Search for a pattern
    match=$( printf "%s" "${text}" | awk /"${pattern}"/ )
    # If nothing found, present an error and exit.
    if [ -z "${match}" ]; then
        printf "Assertion failure: \n\"%s\"\n\ndoesn't contain pattern:\n
\"%s\"\n\n" "${text}" "${pattern}"
        printf "${detailed_err}\n" "\"${pattern}\""
        clean_exit 1
    fi
}

# Begins a test by prining its name.
test_start() {
    TEST_NAME=${1}
    if [ -z ${TEST_NAME} ]; then
        test_lib_error "test_start requires test name as an argument"
        clean_exit 1
    fi
    echo ${dash_e} "${clear}${blue}START TEST ${TEST_NAME}${clear}"
}

# Prints test result an cleans up after the test.
test_finish() {
    local exit_code=${1}  # Exit code to be returned by the exit function.
    if [ ${exit_code} -eq 0 ]; then
        cleanup
        echo ${dash_e} "${green}PASSED ${TEST_NAME}${clear}"
    else
    if [ ${exit_code} -eq 2 ]; then
        cleanup
        echo ${dash_e} "${yellow}SKIPPED ${TEST_NAME}${clear}"
    else
        # Dump log file for debugging purposes if specified and exists.
        # Otherwise the code below would simply call cat.
        if [ -n "${LOG_FILE}" -a -s "${LOG_FILE}" ]; then
            printf "Log file dump:\n"
            cat ${LOG_FILE}
        fi
        cleanup
        echo ${dash_e} "${red}FAILED ${TEST_NAME}${clear}"
    fi
    fi
    echo ""
}

# Stores the configuration specified as a parameter in the configuration
# file which name has been set in the ${CFG_FILE} variable.
create_config() {
    local cfg="${1}"  # Configuration string.
    if [ -z ${CFG_FILE} ]; then
        test_lib_error "create_config requires CFG_FILE variable be set"
        clean_exit 1

    elif [ -z "${cfg}" ]; then
        test_lib_error "create_config requires argument holding a configuration"
        clean_exit 1
    fi
    printf "Creating configuration file: %s.\n" ${CFG_FILE}
    printf "%b" ${cfg} > ${CFG_FILE}
}

# Sets Kea logger to write to the file specified by the global value
# ${LOG_FILE}.
set_logger() {
    if [ -z ${LOG_FILE} ]; then
        test_lib_error "set_logger requies LOG_FILE variable be set"
        clean_exit 1
    fi
    printf "Log will be stored in %s.\n" ${LOG_FILE}
    export KEA_LOGGER_DESTINATION=${LOG_FILE}
}

# PID file path is by default <kea-install-dir>/var/kea, but can be
# overriden by the environmental variable.
PID_FILE_PATH=${prefix}/var/kea/
if [ ! -z ${KEA_PIDFILE_DIR} ]; then
    PID_FILE_PATH="${KEA_PIDFILE_DIR}"
fi

# Checks if specified process is running.
#
# This function uses PID file to obtain the PID and then calls
# 'kill -0 <pid>' to check if the process is alive.
# The PID files are expected to be located in the ${PID_FILE}.
#
# Return value:
#   _GET_PID: holds a PID if process is running
#   _GET_PIDS_NUM: holds 1 if process is running, 0 otherwise
get_pid() {
    local proc_name=${1}     # Process name

    # PID file name includes process name. The process name is required.
    if [ -z ${proc_name} ]; then
        test_lib_error "get_pid requires process name"
        clean_exit 1
    fi

    # Get the absolute location of the PID file for the specified process
    # name.
    abs_pidfile_path="${PID_FILE}"
    _GET_PID=0
    _GET_PIDS_NUM=0

    # If the PID file exists, get the PID and see if the process is alive.
    if [ -e ${abs_pidfile_path} ]; then
        pid=$( cat $abs_pidfile_path )
        kill -0 ${pid} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            _GET_PID=${pid}
            _GET_PIDS_NUM=1
        fi
    fi
}

# Kills processes specified by name.
#
# This function kills all processes having a specified name.
# It uses 'pgrep' to obtain pids of those processes.
# This function should be used when identifying process by
# the value in its PID file is not relevant.
kill_processes_by_name() {
    local proc_name=${1} # Process name
    if [ -z ${proc_name} ]; then
        test_lib_error "get_pids requires process name"
        clean_exit 1
    fi
    # Obtain PIDs of running processes.
    local pids=$( pgrep ${proc_name} )
    # For each PID found, send kill signal.
    for pid in ${pids}
    do
        printf "Shutting down process ${proc_name} having pid %d.\n" ${pid}
        kill -9 ${pid}
    done
}

# Returns the number of occurrences of the Kea log message in the log file.
# Return value:
#   _GET_LOG_MESSAGES: number of log message occurrences.
get_log_messages() {
    local msg="${1}"  # Message id, e.g. DHCP6_SHUTDOWN
    if [ -z ${msg} ]; then
        test_lib_error "get_log_messages require message identifier"
        clean_exit 1
    fi
    _GET_LOG_MESSAGES=0
    # If log file is not present, the number of occurrences is 0.
    if [ -s ${LOG_FILE} ]; then
        # Grep log file for the logger message occurrences and remove
        # whitespaces, if any.
        _GET_LOG_MESSAGES=$( grep -o ${msg} ${LOG_FILE} | wc -w | tr -d " ")
    fi
}

# Returns the number of server configurations performed so far. Also
# returns the number of configuration errors.
# Return values:
#   _CHECK_CLIENT_STARTED: number of configurations so far.
#   _CHECK_CLIENT_EXIT: number of configuration errors.
check_client_started() {
    # Grep log file for CONFIG_COMPLETE occurrences. There should
    # be one occurrence per (re)configuration.
    _CHECK_CLIENT_STARTED=$( grep -o "Listening on " ${LOG_FILE} | wc -l )
    # Grep log file for CONFIG_LOAD_FAIL to check for configuration
    # failures.
    _CHECK_CLIENT_EXIT=$( grep -o "exiting" ${LOG_FILE} | wc -l )
    # Remove whitespaces
    ${_CHECK_CLIENT_STARTED##*[! ]}
    ${_CHECK_CLIENT_EXIT##*[! ]}
}

grep_file() {
    local file="${1}" # file to grep.
    local expr="${2}" # Expression to grep for.
    local expected="${3}" # expected number of occurences

    if [ ! -e ${file} ]; then
        printf "ERROR: file [%s] does not exist, can't grep\n" ${file}
        clean_exit 1
    fi

    _GREP_FILE_COUNT=$( grep -o "${expr}" ${file} | wc -l )
    printf "File %s contains %d instance(s) of \"%s\"\n" "${file}" "${_GREP_FILE_COUNT}" "${expr}"

    if [ ${_GREP_FILE_COUNT} != ${expected} ]; then
        printf "ERROR: File %s expected to contain %d instances of '%s', but contains %d\n" \
               "${file}" "${expected}" "${expr}" "${_GREP_FILE_COUNT}"
        clean_exit 1
    fi
}

# Performs cleanup after test.
# It shuts down running Kea processes and removes temporary files.
# The location of the log file and the configuration files should be set
# in the ${LOG_FILE}, ${CFG_FILE} variables recpectively, prior to calling
# this function.
cleanup() {

    # If there is no PROCS set, just return
    if [ -z "${PROCS}" ]; then
        return
    fi

    # PROCS holds the name of all processes. Shut down each of them if running.
    for proc_name in ${PROCS}
    do
        get_pid ${proc_name}
        # Shut down running Kea process.
        if [ ${_GET_PIDS_NUM} -ne 0 ]; then
            printf "Shutting down proccess having pid %d.\n" ${_GET_PID}
            kill -9 ${_GET_PID}
        fi
    done

    # Remove temporary files.
    #rm -rf ${LOG_FILE}
    # Use asterisk to remove all files starting with the given name,
    # in case the LFC has been run. LFC creates files with postfixes
    # appended to the lease file name.
    if [ ! -z "${LEASE_FILE}" ]; then
        rm -rf ${LEASE_FILE}*
    fi
    rm -rf ${CFG_FILE}
}

# Exists the test in the clean way.
# It performes the cleanup and prints whether the test has passed or failed.
# If a test fails, the Kea log is dumped.
clean_exit() {
    exit_code=${1}  # Exit code to be returned by the exit function.
    case ${exit_code} in
        ''|*[!0-9]*)
            test_lib_error "argument passed to clean_exit must be a number" ;;
    esac
    # Print test result and perform a cleanup
    test_finish ${exit_code}
    exit ${exit_code}
}

# Starts a process in background using a configuration file specified
# in the global variable ${CFG_FILE} (with logging to ${LOG_FILE}.
start_kea() {
    local bin=${1}
    if [ -z ${bin} ]; then
        test_lib_error "binary name must be specified for start_kea"
        clean_exit 1
    fi
    local extra_params=${2}
    printf "Running command %s.\n" "\"${bin} -cf ${CFG_FILE}\ -lf ${LEASE_FILE} -pf ${PID_FILE} -sf ${SCRIPT_FILE} -d ${extra_params} ${IFACE} &> ${LOG_FILE}\""
    ${bin} -cf ${CFG_FILE} -lf ${LEASE_FILE} -pf ${PID_FILE} -sf ${SCRIPT_FILE} -d ${extra_params} ${IFACE} &> ${LOG_FILE} &
}

# Waits with timeout for Kea to start.
# This function repeatedly checs if the Kea log file has been created
# and is non-empty. If it is, the function assumes that Kea has started.
# It doesn't check the contents of the log file though.
# If the log file doesn't exist the function sleeps for a second and
# checks again. This is repeated until timeout is reached or non-empty
# log file is found. If timeout is reached, the function reports an
# error.
# Return value:
#    _WAIT_FOR_KEA: 0 if Kea hasn't started, 1 otherwise
wait_for_kea() {
    local timeout=${1} # Desired timeout in seconds.
    case ${timeout} in
        ''|*[!0-9]*)
            test_lib_error "argument passed to wait_for_kea must be a number"
            clean_exit 1 ;;
    esac
    local loops=0 # Loops counter
    _WAIT_FOR_KEA=0
    test_lib_info "wait_for_kea " "skip-new-line"
    while [ ! -s ${LOG_FILE} ] && [ ${loops} -le ${timeout} ]; do
        printf "."
        sleep 1
        loops=$( expr $loops + 1 )
    done
    printf "\n"
    if [ ${loops} -le ${timeout} ]; then
        _WAIT_FOR_KEA=1
    fi
}

# Waits for a specific message to occur in the Kea log file.
# This function is called when the test expects specific message
# to show up in the log file as a result of some action that has
# been taken. Typically, the test expects that the message
# is logged when the SIGHUP or SIGTERM signal has been sent to the
# Kea process.
# This function waits a specified number of seconds for the number
# of message occurrences to show up. If the expected number of
# message doesn't occur, the error status is returned.
# Return value:
#    _WAIT_FOR_MESSAGE: 0 if the message hasn't occurred, 1 otherwise.
wait_for_message() {
    local timeout=${1}     # Expected timeout value in seconds.
    local message="${2}"   # Expected message id.
    local occurrences=${3} # Number of expected occurrences.

    # Validate timeout
    case ${timeout} in
        ''|*[!0-9]*)
            test_lib_error "argument timeout passed to wait_for_message must \
be a number"
        clean_exit 1 ;;
    esac

    # Validate message
    if [ -z "${message}" ]; then
        test_lib_error "message id is a required argument for wait_for_message"
        clean_exit 1
    fi

    # Validate occurrences
    case ${occurrences} in
        ''|*[!0-9]*)
            test_lib_error "argument occurrences passed to wait_for_message \
must be a number"
        clean_exit 1 ;;
    esac

    local loops=0          # Number of loops performed so far.
    _WAIT_FOR_MESSAGE=0
    test_lib_info "wait_for_message '${message}': " "skip-new-line"
    # Check if log file exists and if we reached timeout.
    while [ ${loops} -le ${timeout} ]; do
        printf "."
        # Check if the message has been logged.
        get_log_messages ${message}
        if [ ${_GET_LOG_MESSAGES} -ge ${occurrences} ]; then
            printf "found\n"
            _WAIT_FOR_MESSAGE=1
            return
        fi
        # Message not recorded. Keep going.
        sleep 1
        loops=$( expr ${loops} + 1 )
    done
    printf "not found\n"
    # Timeout.
}

# Waits for server to be down.
# Return value:
#    _WAIT_FOR_PROCESS_DOWN: 1 if server is down, 0 if timeout occurred and the
#                             server is still running.
wait_for_process_down() {
    local timeout=${1}    # Timeout specified in seconds.
    local proc_name=${2}  # Server process name.

    case ${timeout} in
        ''|*[!0-9]*)
            test_lib_error "argument passed to wait_for_process_down must be a number"
            clean_exit 1 ;;
    esac
    local loops=0 # Loops counter
    _WAIT_FOR_PROCESS_DOWN=0
    test_lib_info "wait_for_process_down ${proc_name}: " "skip-new-line"
    while [ ${loops} -le ${timeout} ]; do
        printf "."
        get_pid ${proc_name}
        if [ ${_GET_PIDS_NUM} -eq 0 ]; then
            printf "\n"
            _WAIT_FOR_PROCESS_DOWN=1
            return
        fi
        sleep 1
        loops=$( expr $loops + 1 )
    done
    printf "\n"
}

# Sends specified signal to the Kea process.
send_signal() {
    local sig=${1}       # Signal number.
    local proc_name=${2} # Process name

    # Validate signal
    case ${sig} in
        ''|*[!0-9]*)
            test_lib_error "signal number passed to send_signal \
must be a number"
        clean_exit 1 ;;
    esac
    # Validate process name
    if [ -z ${proc_name} ]; then
        test_lib_error "send_signal requires process name be passed as argument"
        clean_exit 1
    fi
    # Get Kea pid.
    get_pid ${proc_name}
    if [ ${_GET_PIDS_NUM} -ne 1 ]; then
        printf "ERROR: expected one process to be started.\
 Found %d processes started.\n" ${_GET_PIDS_NUM}
        clean_exit 1
    fi
    printf "Sending signal ${sig} to process (pid=%s).\n" ${_GET_PID}
    # Actually send a signal.
    kill -${sig} ${_GET_PID}
}

# Verifies that a server is up running by its PID file
# The PID file is constructed from the given config file name and
# binary name.  If it exists and the PID it contains refers to a
# live process it sets _SERVER_PID_FILE and _SERVER_PID to the
# corresponding values.  Otherwise, it emits an error and exits.
verify_server_pid() {
    local bin_name="${1}" # binary name of the server
    local cfg_file="${2}" # config file name

    # We will construct the PID file name based on the server config
    # and binary name
    if [ -z ${bin_name} ]; then
        test_lib_error "verify_server_pid requires binary name"
        clean_exit 1
    fi

    if [ -z ${cfg_file} ]; then
        test_lib_error "verify_server_pid requires config file name"
        clean_exit 1
    fi

    # Only the file name portion of the config file is used, try and
    # extract it. NOTE if this "algorithm" changes this code will need
    # to be updated.
    fname=`basename ${cfg_file}`
    fname=`echo $fname | cut -f1 -d'.'`

    if [ -z ${fname} ]; then
        test_lib_error "verify_server_pid could not extract config name"
        clean_exit 1
    fi

    # Now we can build the name:
    pid_file="$KEA_PIDFILE_DIR/$fname.$bin_name.pid"

    if [ ! -e ${pid_file} ]; then
        printf "ERROR: PID file:[%s] does not exist\n" ${pid_file}
        clean_exit 1
    fi

    # File exists, does its PID point to a live process?
    pid=`cat ${pid_file}`
    kill -0 ${pid}
    if [ $? -ne 0 ]; then
        printf "ERROR: PID file:[%s] exists but PID:[%d] does not\n" \
               ${pid_file} ${pid}
        clean_exit 1
    fi

    # Make the values accessible to the caller
    _SERVER_PID="${pid}"
    _SERVER_PID_FILE="${pid_file}"
}

# This test verifies that the binary is reporting its version properly.
version_test() {
    test_name=${1}  # Test name

    # Log the start of the test and print test name.
    test_start ${test_name}

    # Remove dangling Kea instances and remove log files.
    cleanup

    REPORTED_VERSION="`${bin_path}/${bin} --version 2>&1`"

    if test "${REPORTED_VERSION}" == "${EXPECTED_VERSION}"; then
        test_finish 0
    else
        printf "ERROR: Expected version ${EXPECTED_VERSION}, got ${REPORTED_VERSION}\n"
        test_finish 1
    fi
}

# This test verifies that the server is using logger variable
# KEA_LOCKFILE_DIR properly (it should be used to point out to the directory,
# where lockfile should be created. Also, "none" value means to not create
# the lockfile at all).
logger_vars_test() {
    test_name=${1}  # Test name

    # Log the start of the test and print test name.
    test_start ${test_name}
    # Remove dangling Kea instances and remove log files.
    cleanup

    # Create bogus configuration file. We don't really want the server to start,
    # just want it to log something and die. Empty config is an easy way to
    # enforce that behavior.
    create_config "{ }"
    printf "Please ignore any config error messages.\n"

    # Remember old KEA_LOCKFILE_DIR
    KEA_LOCKFILE_DIR_OLD=${KEA_LOCKFILE_DIR}

    # Set lockfile directory to current directory.
    KEA_LOCKFILE_DIR=.

    # Start Kea.
    start_kea ${bin_path}/${bin}

    # Wait for Kea to process the invalid configuration and die.
    sleep 1

    # Check if it is still running. It should have terminated.
    get_pid ${bin}
    if [ ${_GET_PIDS_NUM} -ne 0 ]; then
        printf "ERROR: expected Kea process to not start. Found %d processes"
        printf " running.\n" ${_GET_PIDS_NUM}

        # Revert to the old KEA_LOCKFILE_DIR value
        KEA_LOCKFILE_DIR=${KEA_LOCKFILE_DIR_OLD}
        clean_exit 1
    fi

    if [ ! -f "./logger_lockfile" ]; then
        printf "ERROR: Expect ${bin} to create logger_lockfile in the\n"
        printf "current directory, but no such file exists.\n"

        # Revert to the old KEA_LOCKFILE_DIR value
        KEA_LOCKFILE_DIR=${KEA_LOCKFILE_DIR__OLD}
        clean_exit 1
    fi

    # Remove the lock file
    rm -f ./logger_lockfile

    # Tell Kea to NOT create logfiles at all
    KEA_LOCKFILE_DIR="none"

    # Start Kea.
    start_kea ${bin_path}/${bin}

    # Wait for Kea to process the invalid configuration and die.
    sleep 1

    # Check if it is still running. It should have terminated.
    get_pid ${bin}
    if [ ${_GET_PIDS_NUM} -ne 0 ]; then
        printf "ERROR: expected Kea process to not start. Found %d processes"
        printf " running.\n" ${_GET_PIDS_NUM}

        # Revert to the old KEA_LOCKFILE_DIR value
        KEA_LOCKFILE_DIR=${KEA_LOCKFILE_DIR_OLD}

        clean_exit 1
    fi

    if [ -f "./logger_lockfile" ]; then
        printf "ERROR: Expect ${bin} to NOT create logger_lockfile in the\n"
        printf "current directory, but the file exists."

        # Revert to the old KEA_LOCKFILE_DIR value
        KEA_LOCKFILE_DIR=${KEA_LOCKFILE_DIR_OLD}

        clean_exit 1
    fi

    # Revert to the old KEA_LOCKFILE_DIR value
    printf "Reverting KEA_LOCKFILE_DIR to ${KEA_LOCKFILE_DIR_OLD}\n"
    KEA_LOCKFILE_DIR=${KEA_LOCKFILE_DIR_OLD}

    test_finish 0
}

# This test verifies server PID file management
# 1. It verifies that upon startup, the server creates a PID file
# 2. It verifies the an attempt to start a second instance fails
# due to pre-existing PID File/PID detection
server_pid_file_test() {
    local server_cfg="${1}"
    local log_id="${2}"

    # Log the start of the test and print test name.
    test_start "${bin}.server_pid_file_test"
    # Remove dangling DHCP4 instances and remove log files.
    cleanup
    # Create new configuration file.
    create_config "${CONFIG}"
    # Instruct server to log to the specific file.
    set_logger
    # Start server
    start_kea ${bin_path}/${bin}
    # Wait up to 20s for server to start.
    wait_for_kea 20
    if [ ${_WAIT_FOR_KEA} -eq 0 ]; then
        printf "ERROR: timeout waiting for %s to start.\n" ${bin}
        clean_exit 1
    fi

    # Verify server is still running
    verify_server_pid ${bin} ${CFG_FILE}

    printf "PID file is [%s],  PID is [%d]" ${_SERVER_PID_FILE} ${_SERVER_PID}

    # Now try to start a second one
    start_kea ${bin_path}/${bin}

    wait_for_message 10 "${log_id}" 1
    if [ ${_WAIT_FOR_MESSAGE} -eq 0 ]; then
        printf "ERROR: Second %s instance started? PID conflict not reported.\n" ${bin}
        clean_exit 1
    fi

    # Verify server is still running
    verify_server_pid ${bin} ${CFG_FILE}

    # All ok. Shut down the server and exit.
    test_finish 0
}
