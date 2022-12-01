#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>


// Savind the foreground processes ids
// Maximum number of foreground processes is 2, when piping is done.
int processes[2];

void signal_handler(int signum);

// What action to take when child processes expire
struct sigaction child = {
	.sa_handler = SIG_DFL, // We want to be able to wait for child processes to wait
	.sa_flags = SA_RESTART | SA_NOCLDWAIT // We want to avoid EINTR, and avoid processes from becoming zombies (relevant for the '&' case)
};

// What action to take when getting a SIGINT
struct sigaction self = {
	.sa_handler = signal_handler
};

void signal_handler(int signum) {
    /**
     * Uppon sigint, we check if we have running foreground processes and terminate them
     * by sending SIGINT
    */
	int i;
	for (i = 0; i < 2; i++) {
		if (processes[i] != 0) {
			kill(processes[i], SIGINT);
			processes[i] = 0;
		}
	}
}


void print_err(void) {
    /**
     * Printing the error encountered by the process
    */
	fprintf(stderr, "%s \n", (char *)strerror(errno));
}

int parent_identify_error(int status) {
    /**
     * Function the shell process runs when checking if an error was encountered
     * during a syscall
    */
	if (status == -1) {
		print_err();
		return 1;
	}
	return 0;
}


int child_identify_error(int status) {
    /**
     * Function the child process runs when checking if an error was encountered
     * during a syscall
    */
	if (status == -1) {
		print_err();
		exit(1);
	}
	return 0;
}


int wait_for_child() {
    /**
     * Waiting for a child process to return
    */
    int wait_return, wait_status, i;
    wait_return = waitpid(-1, &wait_status, 0); // wait for the first process to return
    if ((wait_return >= 0) || (errno == ECHILD) || (errno == EINTR)) {
        // If one of the "good" cases was encountered, we remove the terminated child pid
        // from the list
		for (i = 0; i < 2; i++) {
			if (processes[i] == wait_return) {
				processes[i] = 0;
			}
		}
		// If we did encounter an error, we just return 0 instead of the PID
		if (wait_return < 0) {
			return 0;
		}
        return wait_return;
    }
    else {
        // If an error has occured, we print it via stderr and exit the 
    	fprintf(stderr, "%s \n", (char *)strerror(errno));
        return -1;
    }
}


int run_in_background(int count, char** arglist) {
    /**
     * Running a process in the background
    */
    int pid;
    arglist[count - 1] = NULL;          // Setting the last argument as NULL (for the child process' sake)
    pid = fork();                       // We fork so execvp won't hijack the process
    if (parent_identify_error(pid)) {
        // If the parent process encountered an error we return 0
    	return 0;
    }
    if (pid == 0) {
        // We're in the child process
        execvp(arglist[0], arglist); // Running the process
        print_err();
        exit(1);
    }
    else {
	    // We're in the parent process, and don't have to wait for the child process to finish running
	    return 1;
    }
}


int pipe_programs(int count, int pipe_symbol_position, char** arglist) {
    /**
     * Piping 2 programs
    */
    int fd[2];
    int first_proc_pid, second_proc_pid, dup2_status, close_status1, close_status2;
    
    arglist[pipe_symbol_position] = NULL; // We remove the pipe symbol, and effectively split the arglist to 2 arglists
    
    /**
     * If we couldn't create a pipe, we print an error and terminate the shell
    */
    if (pipe(fd) < 0) {
    	print_err();
        return 0;
    }
    
    first_proc_pid = fork();
    if (parent_identify_error(first_proc_pid)) {
        // If we couldn't create a child process, we terminate and return
	    return 0;
	}
    if (first_proc_pid == 0) {
        // We're in the (first) child process
        dup2_status = dup2(fd[1], fileno(stdout)); // We set the output of the program to go to the pipe
        child_identify_error(dup2_status);
        close_status1 = close(fd[0]);
        child_identify_error(close_status1);
        close_status2 = close(fd[1]);
        child_identify_error(close_status2);
        execvp(arglist[0], arglist);
        // We only reach here if an error occurs
        print_err();
        exit(1);
    }
    else {
    	processes[0] = first_proc_pid;
        // We're in the parent process
        second_proc_pid = fork();
	    if (parent_identify_error(second_proc_pid)) {
	    	return 0;
	    }
        if (second_proc_pid == 0) {
            // We're in the (second) child process
		    dup2_status = dup2(fd[0], fileno(stdin)); // We set stdin to actually be the output of the pipe
		    child_identify_error(dup2_status);
            close_status1 = close(fd[0]);
            close_status2 = close(fd[1]);
            child_identify_error(close_status1);
	        child_identify_error(close_status2);
            execvp(*(arglist + pipe_symbol_position + 1), arglist + pipe_symbol_position + 1);
            // We only reach here if an error occurs
            print_err();
            exit(1);
        }
        else {
   	    	processes[1] = second_proc_pid;
            // We're in the parent process
            close_status1 = close(fd[0]);
            close_status2 = close(fd[1]);
            if (parent_identify_error(close_status1)) {
            	return 0;
            }
	        if (parent_identify_error(close_status2)) {
	        	return 0;
	        }
	        
	        // We remove the first process that finished running
	        if (wait_for_child() == -1) {
	            return 0;
    	    }
	        // We remove the second process that finished running	        	        
	        if (wait_for_child() == -1) {
	            return 0;
    	    }
	        // We remove any process that we didn't already (due to an internal process error for example)
	        processes[0] = 0;
   	        processes[1] = 0;
            return 1;
        }
    }
}


int program_output_redirection(int count, int redirect_symbol_position, char** arglist) {
    /**
     * Function for redirecting a program's stdout > file
    */
    int pid, dup2_status;
    FILE *open_file;

    pid = fork();
    if (parent_identify_error(pid)) {
    	return 0;
    }
    if (pid == 0) {
        // We're inside the child process
        open_file = fopen(arglist[redirect_symbol_position + 1], "w+"); // we open the file, creating it if it doesn't exist
        if (open_file == NULL) {
        	print_err();
        	exit(1);
        }
        else {
	        arglist[redirect_symbol_position] = NULL;
	        dup2_status = dup2(fileno(open_file), fileno(stdout)); // We set stdout to write to the file.
	        if (fclose(open_file) == EOF) {
		        open_file = NULL;
		        print_err();
		        exit(1);
	        }
	        open_file = NULL;
	        child_identify_error(dup2_status);
	        execvp(arglist[0], arglist);
	        print_err();
	        exit(1);
        }
    }
    else {
        // We're in the parent process, waiting for the child process to finish running
    	processes[0] = pid;
    	if (wait_for_child() == -1) {
            return 0;
        }
    	processes[0] = 0;
     	processes[1] = 0;
        return 1;
    }
}


int run_program(int count, char** arglist) {
    /**
     * Simply running a program
    */
    int pid;
    
    pid = fork();
    if (parent_identify_error(pid)) {
    	return 0;
    }
    if (pid == 0) {
        // We're inside the child process
        execvp(arglist[0], arglist);
        print_err();
        exit(1);
    }
    else {
    	processes[0] = pid;
        // Inside the parent process
        if (wait_for_child() == -1) {
            return 0;
        }
    	processes[0] = 0;
     	processes[1] = 0;
        return 1;
    }
}



// arglist - a list of char* arguments (words) provided by the user
// it contains count+1 items, where the last item (arglist[count]) and *only* the last is NULL
// RETURNS - 1 if should continue, 0 otherwise
int process_arglist(int count, char** arglist) {
    int i;
    // Case 1: background
    // if the last argument is '&', we want to run the program in the background
    if (*arglist[count - 1] == '&') {
        return run_in_background(count, arglist);
    }

    // Case 2: piping
    // If we encounter a '|' symbol, it means we're piping.
    for (i = 0; i < count; i++) {
        if (*arglist[i] == '|') {
            return pipe_programs(count, i, arglist);
        }
    }

    // Case 3: redirect
    // If we encounter a '>' symbol, it means we're redirecting the output
    for (i = 0; i < count; i++) {
        if (*arglist[i] == '>') {
            return program_output_redirection(count, i, arglist);
        }
    }
    // Case 4: simply run the program
    return run_program(count, arglist);
}

// prepare and finalize calls for initialization and destruction of anything required
int prepare(void) {
	processes[0] = 0;
	processes[1] = 0;
//	signal(SIGCHLD, SIG_IGN);
	sigaction(SIGCHLD, &child, NULL); // We don't want SIGCHLD to kill the shell process
	sigaction(SIGINT, &self, NULL);   // We set the custom handler for SIGINT
    return 0;
}

int finalize(void) {
    // We kill all running child processes
	signal_handler(SIGKILL);
    // We set the SIGINT and SIGCHLD back to default
    signal(SIGCHLD, SIG_DFL);
	signal(SIGINT, SIG_DFL);
    return 0;
}
