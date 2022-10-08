/* Simple Shell (sish)
 *
 * GENERAL COMMAND STRUCTURE
 * cmd_1 [args...] | ... | cmd_n [args...] [>[>] filename] [&]
 *
 * For example:
 *   ls -l | grep '.*.txt' | wc -l >> out.txt &
 *
 * The maximum number of steps n (i.e. one more than the number of pipe characters) is given by MAX_STEPS. There is no
 * limit on the length or number of arguments per step, but the total length of one command is set by LINECAP.
 *
 * Commands can have any amount of whitespace (including none at all) between different steps. However, there must be
 * whitespace between different arguments within the same step. For example, the commands `ls -l|wc -m>out.txt&` and
 * `  ls  -l  |  wc  -m  >  out.txt  &  ` are both valid, but `ls-l|wc-m>out.txt&` will fail (unless you happen to have
 * commands called `ls-l` and `wc-m` in your PATH). Whether or not a character is whitespace is determined using
 * isspace(3).
 *
 *
 * QUOTES
 * Either single quotes (') or double quotes (") may be used.
 *
 *
 * BACKGROUND
 * The background symbol must come at the very end of the command (excluding whitespace) and must not occur more than
 * once.
 *
 *
 * OUTPUT REDIRECTION
 * If the output file already exists, > will overwrite it while >> will append. If the output file does not yet exist,
 * both methods of redirection will create the file.
 *
 * The redirection symbol and filename must come at the end of the command (excluding the background symbol '&' and
 * whitespace). There can only be one output file for a given command.
 */


#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


#define LINECAP 65535  // Maximum number of characters in one command (excluding newline)
#define MAX_STEPS 20  // Maximum number of steps in a pipeline


struct process {
	pid_t pid;
	struct process *next;
	struct process *prev;
};

struct job {
	int job_id;
	pid_t pgid;
	char *full_text;
	struct process *processes;
	struct job *prev;
	struct job *next;
};

struct pipeline {
	// Array of NULL-terminated arrays of arguments (including command name)
	char **steps[MAX_STEPS];
	size_t num_steps;
	char *out_file;
	bool append;
	bool background;
};

typedef void (*command_runner)(char **);


bool waiting_for_input = false;
pid_t host_shell_pid;  // PID of the host shell (as opposed to processes that are created for running commands)
char *current_working_dir = NULL;  // Absolute path of the current working directory
struct job *first_job = NULL;  // Head of a linked list of jobs
struct pipeline *global_pipeline = NULL;  // Current pipeline (global so that it can be freed on exit)


// ---------------------------------------------------------------------------------------------------------------------
// General
// ---------------------------------------------------------------------------------------------------------------------
void *malloc_or_exit(size_t n) {
	void *p = malloc(n);

	if (p == NULL) {
		fprintf(stderr, "Failed to allocate memory.\n");
		exit(EXIT_FAILURE);
	}

	return p;
}

void print_signal_safe(char *msg) {
	// Use write() instead of printf() for code that is called from within a signal handler. printf() is not
	// async-signal-safe.
	write(1, msg, strlen(msg));
}

void trim_left(char **s) {
	size_t length = strlen(*s);
	for (size_t i = 0; i < length; i++) {
		if (!isspace((*s)[i])) break;

		(*s)++;
	}
}

void trim_right(char **s) {
	size_t length = strlen(*s);
	for (int i = length - 1; i >= 0; i--) {
		if (!isspace((*s)[i])) break;

		(*s)[i] = '\0';
	}
}

void trim(char **s) {
	// Trim the left side first so that the pointer is left unchanged for all-whitespace strings
	trim_right(s);
	trim_left(s);
}

void print_prompt() {
	print_signal_safe("[sish] ");
	print_signal_safe(current_working_dir);
	print_signal_safe(" > ");
}


// ---------------------------------------------------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------------------------------------------------
struct pipeline *create_empty_pipeline() {
	struct pipeline *ppl = malloc_or_exit(sizeof(struct pipeline));

	ppl->steps[0] = NULL;
	ppl->num_steps = 0;
	ppl->out_file = NULL;
	ppl->append = false;
	ppl->background = false;

	return ppl;
}

char *pipeline_to_string(struct pipeline *ppl) {
	// Figure out how much memory I need to allocate
	size_t length = 0;
	for (size_t s = 0; s < ppl->num_steps; s++) {
		char **step = ppl->steps[s];
		for (int t = 0; step[t] != NULL; t++) {
			// Token plus one space after it
			length += strlen(step[t]) + 1;
		}
	}
	// Pipe characters (each with one trailing space)
	length += 2 * (ppl->num_steps - 1);
	// Redirection
	if (ppl->out_file != NULL) {
		// '>' character plus space plus filename plus null terminator
		length += strlen(ppl->out_file) + 3;
	}

	char *full_text = malloc_or_exit(length);

	// Copy everything over
	size_t current_idx = 0;
	for (size_t s = 0; s < ppl->num_steps; s++) {
		if (s != 0) {
			strcpy(full_text + current_idx, "| ");
			current_idx += 2;
		}
		char **step = ppl->steps[s];
		for (int t = 0; step[t] != NULL; t++) {
			strcpy(full_text + current_idx, step[t]);
			current_idx += strlen(step[t]) + 1;
			// Replace the null terminator after the token with a space
			full_text[current_idx-1] = ' ';
		}
	}
	// Redirection
	if (ppl->out_file != NULL) {
		strcpy(full_text + current_idx, "> ");
		current_idx += 2;
		strcpy(full_text + current_idx, ppl->out_file);
	}
	else {
		// Replace the space after the last token with null terminator
		full_text[current_idx-1] = '\0';
	}

	return full_text;
}

struct job *pipeline_to_job(int job_id, pid_t pgid, struct pipeline *ppl) {
	struct job *job = malloc_or_exit(sizeof(struct job));

	job->job_id = job_id;
	job->pgid = pgid;
	job->full_text = pipeline_to_string(ppl);
	job->processes = NULL;
	job->prev = NULL;
	job->next = NULL;

	return job;
}

void free_pipeline(struct pipeline *ppl) {
	for (size_t i = 0; i < ppl->num_steps; i++) {
		for (int j = 0; ppl->steps[i][j] != NULL; j++) {
			free(ppl->steps[i][j]);
		}
		free(ppl->steps[i]);
	}

	if (ppl->out_file != NULL) free(ppl->out_file);

	free(ppl);
}


// ---------------------------------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------------------------------
void free_process(struct process *proc) {
	free(proc);
}

void free_job(struct job *job) {
	free(job->full_text);

	struct process *current = job->processes;
	while (current != NULL) {
		struct process *proc_to_free = current;
		current = current->next;
		free_process(proc_to_free);
	}

	free(job);
}

struct job *record_job(struct job **head, pid_t pgid, struct pipeline *ppl) {
	if (*head == NULL) {
		// Start job IDs at 1 (not at 0: atoi() outputs 0 on error and we want to be able to tell when that happens)
		*head = pipeline_to_job(1, pgid, ppl);
		return *head;
	}
	else {
		struct job *current = *head;
		while (current->next != NULL) current = current->next;

		// Just let job ID be one more than the ID of the last existing job (which is always the maximum ID)
		struct job *job = pipeline_to_job(current->job_id + 1, pgid, ppl);
		current->next = job;
		job->prev = current;
		return job;
	}
}

struct process *new_process(pid_t pid) {
	struct process *proc = malloc_or_exit(sizeof(struct process));

	proc->pid = pid;
	proc->next = NULL;
	proc->prev = NULL;

	return proc;
}

void add_process_to_job(struct job *job, pid_t pid) {
	if (job->processes == NULL) {
		job->processes = new_process(pid);
	}
	else {
		struct process *current = job->processes;
		while (current->next != NULL) current = current->next;

		current->next = new_process(pid);
		current->next->prev = current;
	}
}

struct job *get_job_by_id(struct job *head, int job_id) {
	struct job *current = head;

	while (current != NULL && current->job_id != job_id) current = current->next;

	return current;
}

void remove_and_free_job(struct job **head, struct job *job) {
	if (job->prev != NULL) {
		job->prev->next = job->next;
	}
	else {
		*head = job->next;
	}
	if (job->next != NULL) {
		job->next->prev = job->prev;
	}

	free_job(job);
}

void remove_and_free_process(struct process **head, struct process *proc) {
	if (proc->prev != NULL) {
		proc->prev->next = proc->next;
	}
	else {
		*head = proc->next;
	}
	if (proc->next != NULL) {
		proc->next->prev = proc->prev;
	}

	free_process(proc);
}

// Removes and frees the process with the given PID, if it exists.
// If the job in which that process is found has no more processes, that job is removed and freed.
void delete_process(struct job **head, pid_t pid) {
	struct job *current_job = *head;
	while (current_job != NULL) {
		struct process *current_proc = current_job->processes;
		while (current_proc != NULL) {
			if (current_proc->pid == pid) {
				remove_and_free_process(&current_job->processes, current_proc);
				if (current_job->processes == NULL) remove_and_free_job(head, current_job);
				return;
			}
			else {
				current_proc = current_proc->next;
			}
		}
		current_job = current_job->next;
	}
}


// ---------------------------------------------------------------------------------------------------------------------
// User input
// ---------------------------------------------------------------------------------------------------------------------
/* Tries to read one line of input from the user. Exits if EOF is reached and returns false if an error occurred.
 */
bool try_get_line(char **lineptr) {
	// Reset errno so that we can tell whether the failure is due to reading EOF or something else
	errno = 0;
	size_t linecap = 0;

	ssize_t length = getline(lineptr, &linecap, stdin);

	if (length < 0 && errno == 0) {
		// getline() probably failed because of EOF caused by user pressing ^D.
		// If so, add a newline (keep parent shell from printing prompt on same line) and exit.
		printf("\n");
		if (*lineptr != NULL) free(*lineptr);
		exit(EXIT_SUCCESS);
	}
	else if (length < 0) {
		// A real error, not the user pressing ^D
		fprintf(stderr, "Unknown error while reading input. Errno is %d\n", errno);
		if (*lineptr != NULL) free(*lineptr);
		return false;
	}
	else if (length - 1 > LINECAP) {
		fprintf(stderr, "Error: Exceeded maximum line length (%d)\n", LINECAP);
		if (*lineptr != NULL) free(*lineptr);
		return false;
	}
	else {
		return true;
	}
}

// Parse user input with a state machine
#define SH_SEEK_STEP 1
#define SH_SEEK_TOKEN 2
#define SH_READ_TOKEN 3
#define SH_SEEK_END 4
#define SH_SEEK_FILE 5
#define SH_READ_FILE 6
#define SH_READ_QUOTED_TOKEN 7
#define SH_READ_QUOTED_FILE 8
#define SH_SEEK_AMPERSAND 9

// token must be null-terminated. token_len should not include the terminating null character.
void save_token(char *token, size_t token_len, char **dest) {
	token[token_len] = '\0';
	*dest = malloc_or_exit(token_len + 1);
	strcpy(*dest, token);
}

// NULL-terminates the list of tokens.
// On failure (MAX_TOKENS exceeded), returns false.
bool try_save_step(char **tokens, int num_tokens, struct pipeline *ppl) {
	if (ppl->num_steps + 1 > MAX_STEPS) {
		fprintf(stderr, "Error: Exceeded max. steps in pipeline (%d)\n", MAX_STEPS);
		return false;
	}

	ppl->steps[ppl->num_steps] = malloc_or_exit((num_tokens + 1) * sizeof(char *));

	for (int i = 0; i < num_tokens; i++) {
		ppl->steps[ppl->num_steps][i] = tokens[i];
	}

	ppl->steps[ppl->num_steps][num_tokens] = NULL;

	ppl->num_steps++;
	return true;
}

// On error, prints an error message and returns false. ppl should not be used in this case.
bool try_parse_input(char *line, struct pipeline *ppl) {
	// Empty input
	trim(&line);
	size_t n = strlen(line);
	if (n == 0) return true;

	// Use a temporary buffer to store the tokens. Since tokens are at least one character long and are
	// whitespace-separated, there cannot be more than ceil(n/2) = floor((n+1)/2) tokens for a command of length n.
	char **tmp_token_list = malloc_or_exit(((n + 1) / 2) * sizeof(char *));

	// Pointer to beginning of current token
	char *token = line;
	// Number of tokens in the current step
	int num_tokens = 0;
	// Index of current character within token
	size_t i = 0;
	// Opening quote character or '\0' for none
	char quote_char = '\0';
	// Parser state
	int state = SH_SEEK_STEP;

	char c;
	while (true) {
		c = token[i];

		// TODO: Make functions for entry/exit to reduce duplication?
		switch (state) {
			// Looking for the start of the next step (this happens at the beginning and after finding a pipe).
			// In this state, we should have i = 0. Increment both pointers until a command is found.
			case SH_SEEK_STEP:
				if (c == '\0') {
					// Assume input is non-empty
					fprintf(stderr, "Syntax error: Expected command but reached end of line\n");
					goto failure;
				}
				else if (c == '|' || c == '&' || c == '>') {
					fprintf(stderr, "Syntax error: Expected command but read '%c'\n", c);
					goto failure;
				}
				else if (isspace(c)) {
					token++;
				}
				else if (c == '"' || c == '\'') {
					token++;

					quote_char = c;

					num_tokens = 0;

					state = SH_READ_QUOTED_TOKEN;
				}
				else {
					num_tokens = 0;

					state = SH_READ_TOKEN;
					i = 1;
				}
				break;
			// Looking for the next token.
			// In this state, we should have i = 0. Increment only the token pointer until a command is found.
			case SH_SEEK_TOKEN:
				if (c == '\0') {
					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					goto success;
				}
				else if (isspace(c)) {
					token++;
				}
				else if (c == '|') {
					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					state = SH_SEEK_STEP;
					token += i + 1;
					i = 0;
				}
				else if (c == '&') {
					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					ppl->background = true;
					state = SH_SEEK_END;

					token++;
				}
				else if (c == '>') {
					// Check for append-only redirection
					if (token[i+1] == '>') {
						ppl->append = true;
						token++;
					}

					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					state = SH_SEEK_FILE;

					token++;
				}
				else if (c == '"' || c == '\'') {
					quote_char = c;

					state = SH_READ_QUOTED_TOKEN;
					token++;
				}
				else {
					state = SH_READ_TOKEN;
					i = 1;
				}
				break;
			// Reading a token.
			// In this state, line should point to the first character in the current token. Increment i until the end
			//   of the token is reached and then null-terminate the token.
			case SH_READ_TOKEN:
				if (c == '\0') {
					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					goto success;
				}
				else if (isspace(c)) {
					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					state = SH_SEEK_TOKEN;
					token += i + 1;
					i = 0;
				}
				else if (c == '|') {
					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					state = SH_SEEK_STEP;
					token += i + 1;
					i = 0;
				}
				else if (c == '&') {
					ppl->background = true;

					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					state = SH_SEEK_END;
					token += i + 1;
					i = 0;
				}
				else if (c == '>') {
					// Check for append-only redirection
					if (token[i+1] == '>') ppl->append = true;

					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					if (!try_save_step(tmp_token_list, num_tokens, ppl)) goto failure;

					state = SH_SEEK_FILE;
					token += i + 1;
					// Append-only redirection: skip the second > as well
					if (ppl->append) token++;
					i = 0;
				}
				else if (c == '"' || c == '\'') {
					fprintf(stderr, "Syntax error: Unexpected opening quote in token\n");
					goto failure;
				}
				else {
					i++;
				}
				break;
			// Reading a token that is wrapped in quotes.
			// Similar to reading a normal token, but treat characters like & as normal characters and require closing
			//   quote.
			case SH_READ_QUOTED_TOKEN:
				if (c == '\0') {
					fprintf(stderr, "Syntax error: Expected closing quote but reached end of line\n");
					goto failure;
				}
				else if (c == quote_char) {
					save_token(token, i, &tmp_token_list[num_tokens]);
					num_tokens++;

					quote_char = '\0';

					state = SH_SEEK_TOKEN;
					token += i + 1;
					i = 0;
				}
				else {
					i++;
				}
				break;
			// Looking for the end of the string (this happens after reading an ampersand).
			// In this state, we should have i = 0. Increment the token pointer until the end of the string is reached.
			case SH_SEEK_END:
				if (c == '\0') {
					goto success;
				}
				else if (isspace(c)) {
					token++;
				}
				else {
					fprintf(stderr, "Syntax error: Expected end of string but read '%c'\n", c);
					goto failure;
				}
				break;
			// Looking for a filename (this happens after reading '>').
			// In this state, we should have i = 0. Increment the token pointer until a filename is found.
			case SH_SEEK_FILE:
				if (c == '\0') {
					fprintf(stderr, "Syntax error: Expected filename but reached end of line\n");
					goto failure;
				}
				else if (isspace(c)) {
					token++;
				}
				else if (c == '|' || c == '&' || c == '>') {
					fprintf(stderr, "Syntax error: Expected filename but read '%c'\n", c);
					goto failure;
				}
				else if (c == '"' || c == '\'') {
					quote_char = c;

					state = SH_READ_QUOTED_FILE;
					token++;
				}
				else {
					state = SH_READ_FILE;
					i = 1;
				}
				break;
			// Reading a filename.
			// In this state, line should point to the first character in the filename. Increment i until the end of
			//   the filename is reached and then seek the end of the string.
			case SH_READ_FILE:
				if (c == '\0') {
					save_token(token, i, &ppl->out_file);

					goto success;
				}
				else if (isspace(c)) {
					save_token(token, i, &ppl->out_file);

					state = SH_SEEK_AMPERSAND;
					token += i + 1;
					i = 0;
				}
				else if (c == '|' || c == '>') {
					fprintf(stderr, "Syntax error: Expected filename but read '%c'\n", c);
					goto failure;
				}
				else if (c == '&') {
					ppl->background = true;

					save_token(token, i, &ppl->out_file);

					state = SH_SEEK_END;
					token += i + 1;
					i = 0;
				}
				else if (c == '"' || c == '\'') {
					fprintf(stderr, "Syntax error: Unexpected opening quote in token\n");
					goto failure;
				}
				else {
					i++;
				}
				break;
			case SH_READ_QUOTED_FILE:
				if (c == '\0') {
					fprintf(stderr, "Syntax error: Expected closing quote but reached end of line\n");
					goto failure;
				}
				else if (c == quote_char) {
					save_token(token, i, &ppl->out_file);

					state = SH_SEEK_AMPERSAND;
					token += i + 1;
					i = 0;
				}
				else {
					i++;
				}
				break;
			case SH_SEEK_AMPERSAND:
				if (c == '\0') {
					goto success;
				}
				else if (isspace(c)) {
					token++;
				}
				else if (c == '&') {
					ppl->background = true;

					token++;

					state = SH_SEEK_END;
				}
				else {
					fprintf(stderr, "Syntax error: Expected ampersand or end of string but read '%c'\n", c);
					goto failure;
				}
				break;
			default:
				fprintf(stderr, "Internal error: Parser reached invalid state '%d'\n", state);
				goto failure;
		}
	}

	failure:
	free(tmp_token_list);
	return false;

	success:
	free(tmp_token_list);
	return true;
}

// Returns NULL on error.
struct pipeline *input_pipeline() {
	char *line = NULL;

	if (!try_get_line(&line)) return NULL;

	struct pipeline *ppl = create_empty_pipeline();

	if (!try_parse_input(line, ppl)) {
		free_pipeline(ppl);
		ppl = NULL;
	}

	// It's ok to free the original pointer because it's passed by value to the function and so isn't changed. If
	// there's any chance the pointer can be changed (e.g. by something like strsep() or trim()), then I need to save a
	// copy before modifying it.
	free(line);

	return ppl;
}


// ---------------------------------------------------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------------------------------------------------
void warn_for_exec_error() {
	char *details;
	switch (errno) {
		case 2:
			details = "file or directory not found";
			break;
		default:
			details = NULL;
			break;
	}

	if (details != NULL) {
		fprintf(stderr, "Failed to execute command. errno is %d (%s).\n", errno, details);
	}
	else {
		fprintf(stderr, "Failed to execute command. errno is %d.\n", errno);
	}
}

void run_pwd(char **argv) {
	if (argv[1] != NULL) fprintf(stderr, "pwd: ignoring extra arguments.\n");

	printf("%s\n", current_working_dir);
}

void run_cd(char **argv) {
	// No args: print working dir
	if (argv[1] == NULL) {
		run_pwd(argv);
		return;
	}

	if (argv[2] != NULL) fprintf(stderr, "cd: ignoring extra arguments.\n");

	int status = chdir(argv[1]);

	if (status == 0) {
		free(current_working_dir);
		current_working_dir = getcwd(NULL, 0);
	}
	else {
		warn_for_exec_error();
	}
}

void run_echo(char **argv) {
	int i = 1;
	while (true) {
		if (argv[i] == NULL) {
			printf("\n");
			break;
		}

		printf("%s ", argv[i]);
		i++;
	}
}

void run_exit(char **argv) {
	if (argv[1] != NULL) {
		fprintf(stderr, "exit: too many arguments. The command will be skipped.\n");
		return;
	}

	exit(EXIT_SUCCESS);
}

void run_fg(char **argv) {
	if (argv[1] == NULL) return;
	if (argv[2] != NULL) fprintf(stderr, "fg: ignoring extra arguments.\n");

	int job_id = atoi(argv[1]);
	// This will also reject commands like 'fg 0', 'fg +0', 'fg " 0 "', etc. That's not the end of the world: job IDs
	// start at 1 so either way it's an error and fg doesn't run.
	if (job_id == 0) {
		fprintf(stderr, "fg: invalid job ID '%s'.\n", argv[1]);
		return;
	}
	struct job *job = get_job_by_id(first_job, job_id);

	if (job == NULL) {
		fprintf(stderr, "fg: no job found with ID %d.\n", job_id);
		return;
	}

	printf("%s\n", job->full_text);
	// Set the selected process group as the foreground group, inform it that it can start reading from stdin again, and wait for the entire process group
	// Assumes that the PID is equal to the PGID and that the process leader is still attached to the terminal via stdin.
	tcsetpgrp(0, job->pgid);
	kill(job->pgid, SIGCONT);
	waitpid(-job->pgid, NULL, 0);
	tcsetpgrp(0, host_shell_pid);
	remove_and_free_job(&first_job, job);
}

void run_jobs(char **argv) {
	bool show_pgids = argv[1] != NULL && strcmp(argv[1], "-l") == 0;
	if (argv[1] != NULL && (!show_pgids || argv[2] != NULL)) fprintf(stderr, "jobs: ignoring extra arguments.\n");

	if (show_pgids) printf(" ID     PGID  command\n");

	struct job *current = first_job;
	while (current != NULL) {
		if (show_pgids) printf("%3d  %7d  %s\n", current->job_id, current->pgid, current->full_text);
		else printf("%3d  %s\n", current->job_id, current->full_text);

		current = current->next;
	}
}

void run_external_command(char **argv) {
	execvp(argv[0], argv);

	// Only get to this point if there's an error
	warn_for_exec_error();
	// Kill the child process
	// Failure to do so will result in many nested shells piling up (pointed out by Gabriel Lacroix)
	exit(errno);
}

// Finds the command runner for the given command.
// Returns true if cmd is a built-in command and false otherwise.
bool get_runner(char *cmd, command_runner *run) {
	if (strcmp(cmd, "cd") == 0) *run = run_cd;
	else if (strcmp(cmd, "echo") == 0) *run = run_echo;
	else if (strcmp(cmd, "exit") == 0) *run = run_exit;
	else if (strcmp(cmd, "fg") == 0) *run = run_fg;
	else if (strcmp(cmd, "jobs") == 0) *run = run_jobs;
	else if (strcmp(cmd, "pwd") == 0) *run = run_pwd;
	else *run = run_external_command;
	
	return *run != run_external_command;
}

void run_pipeline(struct pipeline *ppl) {
	if (ppl->num_steps <= 0) return;

	// Decide where to send output from final step
	FILE *out_file_stream = NULL;
	int final_fd_out = 1;
	if (ppl->out_file != NULL) {
		char *mode = ppl->append ? "a" : "w";
		out_file_stream = fopen(ppl->out_file, mode);
		if (out_file_stream == NULL) {
			fprintf(stderr, "Failed to open file '%s' for redirection.\n", ppl->out_file);
			return;
		}
		final_fd_out = fileno(out_file_stream);
	}

	// Launch each step
	int pgid = 0;
	int pipefd[2];
	for (size_t i = 0; i < ppl->num_steps; i++) {
		bool is_first_step = i == 0;
		bool is_final_step = i == ppl->num_steps - 1;

		int fd_in = is_first_step ? 0 : pipefd[0];

		if (!is_final_step) pipe(pipefd);

		int fd_out = is_final_step ? final_fd_out : pipefd[1];

		struct job *job;
		command_runner run;
		bool builtin = get_runner(ppl->steps[i][0], &run);
		// Single builtin: run it in the same process
		// Ignore & here
		if (builtin && ppl->num_steps == 1) {
			// Rewire stdout
			int saved_stdout = fd_out != 1 ? dup(1) : 0;
			dup2(fd_out, 1);  // No effect if fd_out = 1

			run(ppl->steps[0]);

			// Restore stdout
			if (saved_stdout) dup2(saved_stdout, 1);
		}
		else {
			pid_t pid = fork();

			// Child
			if (pid == 0) {
				dup2(fd_in, 0);  // If fd_in = 0, this has no effect
				dup2(fd_out, 1);
				// There is no pipe for the last step, so no need to close it
				if (!is_final_step) {
					close(pipefd[0]);
					close(pipefd[1]);
				}

				run(ppl->steps[i]);

				// End the process in case the command runner didn't (for a builtin)
				exit(EXIT_SUCCESS);
			}

			// Parent
			// Close the pipe file descriptors once they've been used
			if (!is_first_step) close(fd_in);
			if (!is_final_step) close(fd_out);

			if (ppl->background) {
				if (is_first_step) {
					// Put each process in the pipeline into the same process group as the first one
					pgid = pid;
					job = record_job(&first_job, pgid, ppl);
				}

				add_process_to_job(job, pid);

				// Put this process in a separate process group
				setpgid(pid, pgid);
			}
		}
	}

	if (!ppl->background) {
		// Only reap processes in the right process group, so that you don't wait on unrelated background processes
		pid_t pid;
		while ((pid = waitpid(0, NULL, 0)) > 0);
	}

	if (out_file_stream != NULL) fclose(out_file_stream);
}


// ---------------------------------------------------------------------------------------------------------------------
// Event handlers (signals or exit)
// ---------------------------------------------------------------------------------------------------------------------
void handle_sigint() {
	// Each process in the current process group should receive SIGINT, so no need to send any kill signals manually

	if (host_shell_pid == getpid()) {
		// It's kind of ugly when the next prompt appears on the same line as the "^C"
		print_signal_safe("\n");
		// It's also nice to re-print the prompt is ^C was pressed while the shell was just waiting for input
		if (waiting_for_input) print_prompt();
	}
	else {
		// exit() is not async-signal-safe, so call _exit() directly. This skips the cleanup for sub-shells, but
		// sub-shells should rarely receive SIGINT anyway (built-in commands are not long-running and it shouldn't take long to call exec() after forking).
		_exit(EXIT_SUCCESS);
	}
}

void bind_signal_handlers() {
	if (signal(SIGINT, handle_sigint) == SIG_ERR) {
		fprintf(stderr, "Failed to bind the signal handler for SIGINT.\n");
		exit(EXIT_FAILURE);
	}
	if (signal(SIGTSTP, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "Failed to bind the signal handler for SIGTSTP.\n");
		exit(EXIT_FAILURE);
	}
	// Ignore SIGTTOU so that the shell can take back control of the terminal after the foreground process terminates
	if (signal(SIGTTOU, SIG_IGN) == SIG_ERR) {
		fprintf(stderr, "Failed to bind the signal handler for SIGTTOU.\n");
		exit(EXIT_FAILURE);
	}
}

// Kills all child processes and frees all memory
void cleanup_at_exit() {
	if (host_shell_pid == getpid()) fprintf(stderr, "exit\n");

	struct job *current = first_job;
	struct job *job_to_remove;
	while (current != NULL) {
		job_to_remove = current;
		current = current->next;

		// Kill all child processes
		// Don't let siblings kill one another. (Maybe it would be cleaner to clear the global variables before forking,
		//   but I think that would take more lines.)
		if (host_shell_pid == getpid()) {
			struct process *current_proc = job_to_remove->processes;
			while (current_proc != NULL) {
				kill(current_proc->pid, SIGTERM);
				current_proc = current_proc->next;
			}
		}
		remove_and_free_job(&first_job, job_to_remove);
	}

	free(current_working_dir);
	if (global_pipeline != NULL) free_pipeline(global_pipeline);
}


// ---------------------------------------------------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------------------------------------------------
int main() {
	host_shell_pid = getpid();

	bind_signal_handlers();

	current_working_dir = getcwd(NULL, 0);

	atexit(cleanup_at_exit);

	while (true) {
		print_prompt();

		waiting_for_input = true;
		global_pipeline = input_pipeline();
		waiting_for_input = false;

		// Reap all background child processes that have terminated
		pid_t pid;
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
			delete_process(&first_job, pid);
		}

		if (global_pipeline == NULL) continue;

		// TODO: How do you support arrow keys? If I can figure out how to handle arrow keys correctly, maybe save the
		// command into a circular buffer to allow user to access command history.

		run_pipeline(global_pipeline);

		free_pipeline(global_pipeline);
		global_pipeline = NULL;
	}
}
