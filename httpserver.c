#include <sys/stat.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <regex.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <semaphore.h>
#include "queue.h"
#include "rwlock.h"
#include "asgn2_helper_funcs.h"

#define BUFSIZE 4096

// Forward declarations
void handle_bad_request(int connection_fd, const char *status_phrase, int status_code);
int is_valid_request(char *buf, regex_t *preg, regmatch_t *pmatch);
int parse_request(char *buf, regmatch_t *pmatch, char *method, char *uri, char *version);
void handle_unsupported_method(int connection_fd, const char *uri, int request_id);
void handle_unsupported_version(int connection_fd, const char *uri, int request_id);
void handle_get_request(int connection_fd, const char *uri, int request_id);
void handle_forbidden_request(int connection_fd, const char *uri, int request_id);
void handle_not_found_request(int connection_fd, const char *uri, int request_id);
void handle_put_request(int connection_fd, const char *uri, int request_id, char *buf,
    ssize_t bytesRead, regmatch_t *pmatch);

int sock_fd = 0;
queue_t *queue;
rwlock_t *log_lock;
ssize_t read_until_here(int fd, char *buf, size_t max_size, const char *delimiter) {
    if (fd < 0 || buf == NULL || delimiter == NULL || max_size == 0) {
        errno = EINVAL;
        return -1; // Invalid arguments
    }

    size_t total_read = 0;
    size_t delimiter_len = strlen(delimiter);
    ssize_t bytes_read;
    bool found = false;

    while (total_read < max_size) {
        // Read one byte at a time to check for the delimiter
        bytes_read = read(fd, buf + total_read, 1);

        if (bytes_read < 0) {
            // Read error
            return -1;
        } else if (bytes_read == 0) {
            // End of file
            break;
        }

        total_read += bytes_read;

        // Check if the delimiter is found
        if (total_read >= delimiter_len
            && memcmp(buf + total_read - delimiter_len, delimiter, delimiter_len) == 0) {
            found = true;
            break;
        }
    }

    if (!found && total_read == max_size) {
        // Buffer full but delimiter not found
        errno = EOVERFLOW;
        return -1;
    }

    return total_read;
}

void *worker(void *arg);
int send_response(int code, const char *status_phrase, int connection_fd, int content_length,
    const char *message_body) {
    char resp_buff[BUFSIZE] = { 0 };

    int hdr_len = snprintf(resp_buff, sizeof(resp_buff),
        "HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n", code, status_phrase, content_length);

    if (hdr_len >= (int) sizeof(resp_buff)) {
        return -1;
    }
    strncpy(resp_buff + hdr_len, message_body, sizeof(resp_buff) - hdr_len - 1);

    size_t total_len = strlen(resp_buff);
    size_t written = 0;

    while (written < total_len) {
        ssize_t chunk = write(connection_fd, resp_buff + written, total_len - written);
        if (chunk < 0) {
            return -1;
        }
        written += chunk;
    }
    return written;
}
void handleCon(int connection_fd) {
    if (connection_fd == -1) {
        return;
    }

    while (1) {
        char buf[2049]; // Buffer for request
        memset(buf, '\0', sizeof(buf));

        ssize_t bytesRead = read_until_here(connection_fd, buf, 2048, "\r\n\r\n");
        if (!bytesRead) {
            handle_bad_request(connection_fd, "Bad Request", 400);
            break;
        }
        regex_t preg;
        regmatch_t pmatch[8];
        if (!is_valid_request(buf, &preg, pmatch)) {
            handle_bad_request(connection_fd, "Bad Request", 400);
            break;
        }
        char method[9] = { 0 }, uri[65] = { 0 }, version[9] = { 0 };
        int request_id = parse_request(buf, pmatch, method, uri, version);
        if (strcmp(method, "PUT") != 0 && strcmp(method, "GET") != 0) {
            handle_unsupported_method(connection_fd, uri, request_id);
            break;
        }

        if (strcmp(version, "HTTP/1.1") != 0) {
            handle_unsupported_version(connection_fd, uri, request_id);
            break;
        }
        if (strcmp(method, "GET") == 0) {
            handle_get_request(connection_fd, uri, request_id);
        } else if (strcmp(method, "PUT") == 0) {
            handle_put_request(connection_fd, uri, request_id, buf, bytesRead, pmatch);
        }
        break;
    }
    char buf[BUFSIZE];
    while (read_n_bytes(connection_fd, buf, BUFSIZE)) {
        ;
    }
}
int is_valid_request(char *buf, regex_t *preg, regmatch_t *pmatch) {
    const char *pattern = "^([a-zA-Z]{1,8}) (/[a-zA-Z0-9.-]{1,63}) "
                          "(HTTP/[0-9]\\.[0-9])\r\n([a-zA-Z0-9.-]{1,128}: [ "
                          "-~]{1,128}\r\n)*(Content-Length: [ "
                          "-~]{1,128}\r\n)?([a-zA-Z0-9.-]{1,128}: [ -~]{1,128}\r\n)*(\r\n)";

    if (regcomp(preg, pattern, REG_EXTENDED | REG_NEWLINE) != 0) {
        fprintf(stderr, "Error compiling regex\n");
        regfree(preg);
        exit(1);
    }
    if (regexec(preg, buf, 8, pmatch, 0) != 0) {
        regfree(preg);
        return 0;
    }
    regfree(preg);
    return 1;
}

int parse_request(char *buf, regmatch_t *pmatch, char *method, char *uri, char *version) {
    strncpy(method, buf + pmatch[1].rm_so, pmatch[1].rm_eo - pmatch[1].rm_so);
    strncpy(uri, buf + pmatch[2].rm_so + 1, pmatch[2].rm_eo - pmatch[2].rm_so - 1);
    strncpy(version, buf + pmatch[3].rm_so, pmatch[3].rm_eo - pmatch[3].rm_so);
    char *header_location = strstr(buf, "\r\nRequest-Id: ");
    if (header_location) {
        char header[129] = { 0 };
        header_location += strlen("\r\nRequest-Id: ");
        int req_dig = 0;
        for (int i = 0; i < 129 && *header_location != '\r'; i++) {
            if (!isdigit(*header_location)) {
                req_dig = 1;
                break;
            }
            header[i] = *header_location;
            header_location++;
        }
        if (!req_dig) {
            return atoi(header);
        }
    }
    return 0;
}

void handle_bad_request(int connection_fd, const char *status_phrase, int status_code) {
    const char *message_body = "Bad Request\n";
    send_response(status_code, status_phrase, connection_fd, strlen(message_body), message_body);
    fprintf(stderr, "BADREQUEST,/?,%d,0\n", status_code);
}

void handle_unsupported_method(int connection_fd, const char *uri, int request_id) {
    const char *message_body = "Not Implemented\n";
    const char *status_phrase = "Not Implemented";
    send_response(501, status_phrase, connection_fd, strlen(message_body), message_body);
    fprintf(stderr, "UNSUPPORTED,/%s,501,%d\n", uri, request_id);
}

void handle_unsupported_version(int connection_fd, const char *uri, int request_id) {
    const char *message_body = "Version Not Supported\n";
    const char *status_phrase = "Version Not Supported";
    send_response(505, status_phrase, connection_fd, strlen(message_body), message_body);
    fprintf(stderr, "UNSUPPORTED,/%s,505,%d\n", uri, request_id);
}
void handle_get_request(int connection_fd, const char *uri, int request_id) {
    reader_lock(log_lock);
    int fd = open(uri, O_RDONLY);
    struct stat s;
    if (stat(uri, &s) == 0 && S_ISDIR(s.st_mode)) {
        close(fd);
        handle_forbidden_request(connection_fd, uri, request_id);
        reader_unlock(log_lock);
        return;
    }
    if (fd == -1) {
        handle_not_found_request(connection_fd, uri, request_id);
        reader_unlock(log_lock);
        return;
    }
    long long file_size = s.st_size;
    const char *message_body = "";
    const char *status_phrase = "OK";
    send_response(200, status_phrase, connection_fd, file_size, message_body);

    struct timeval timeout = { 1, 0 }; // Timeout for socket read
    setsockopt(connection_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));
    pass_n_bytes(fd, connection_fd, 2147483647); // Transfer file

    fprintf(stderr, "GET,/%s,200,%d\n", uri, request_id);
    reader_unlock(log_lock);
}

void handle_forbidden_request(int connection_fd, const char *uri, int request_id) {
    const char *message_body = "Forbidden\n";
    const char *status_phrase = "Forbidden";
    send_response(403, status_phrase, connection_fd, strlen(message_body), message_body);
    fprintf(stderr, "GET,/%s,403,%d\n", uri, request_id);
}
void handle_not_found_request(int connection_fd, const char *uri, int request_id) {
    const char *message_body = "Not Found\n";
    const char *status_phrase = "Not Found";
    send_response(404, status_phrase, connection_fd, strlen(message_body), message_body);
    fprintf(stderr, "GET,/%s,404,%d\n", uri, request_id);
}
void handle_put_request(int connection_fd, const char *uri, int request_id, char *buf,
    ssize_t bytesRead, regmatch_t *pmatch) {
    regex_t preg;
    regmatch_t pmatch_put[7];

    const char *put_pattern = "^([a-zA-Z]{1,8}) (/[a-zA-Z0-9.-]{1,63}) "
                              "(HTTP/[0-9]\\.[0-9])\r\n([a-zA-Z0-9.-]{1,128}: [ "
                              "-~]{1,128}\r\n)*(Content-Length: [ "
                              "-~]{1,128}\r\n){1}([a-zA-Z0-9.-]{1,128}: [ -~]{1,128}\r\n)*\r\n";

    if (regcomp(&preg, put_pattern, REG_EXTENDED | REG_NEWLINE) != 0) {
        fprintf(stderr, "Error compiling regex\n");
        regfree(&preg);
        exit(1);
    }
    if (regexec(&preg, buf, 7, pmatch_put, 0) != 0) {
        handle_bad_request(connection_fd, "Bad Request", 400);
        regfree(&preg);
        return;
    }
    regfree(&preg);
    char *content_length = buf + pmatch_put[5].rm_so + 16; // Skip "Content-Length: "
    char content_length_str[129] = { 0 };
    int notdigit = 0;
    for (int i = 0; *content_length != '\r'; content_length++) {
        if (!isdigit(*content_length)) {
            handle_bad_request(connection_fd, "Bad Request", 400);
            notdigit = 1;
            fprintf(stderr, "PUT,/%s,400,%d\n", uri, request_id);
            break;
        }
        content_length_str[i] = *content_length;
        i++;
    }
    if (notdigit)
        return;
    int content_length_int = atoi(content_length_str);
    int created = 0;
    writer_lock(log_lock);

    int fd = open(uri, O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
        created = 1;
        fd = open(uri, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    }
    struct stat s;
    if (stat(uri, &s) == 0 && S_ISDIR(s.st_mode)) {
        close(fd);
        handle_forbidden_request(connection_fd, uri, request_id);
        writer_unlock(log_lock);
        return;
    }
    int bytesWritten = write_n_bytes(fd, buf + pmatch[7].rm_eo, bytesRead - pmatch[7].rm_eo);
    struct timeval timeout = { 1, 0 };
    setsockopt(connection_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout, sizeof(timeout));
    pass_n_bytes(connection_fd, fd, content_length_int - bytesWritten);
    if (created) {
        const char *message_body = "Created\n";
        const char *status_phrase = "Created";
        send_response(201, status_phrase, connection_fd, strlen(message_body), message_body);
        fprintf(stderr, "PUT,/%s,201,%d\n", uri, request_id);
    } else {
        const char *message_body = "OK\n";
        const char *status_phrase = "OK";
        send_response(200, status_phrase, connection_fd, strlen(message_body), message_body);
        fprintf(stderr, "PUT,/%s,200,%d\n", uri, request_id);
    }
    writer_unlock(log_lock);
    close(fd);
}

void *worker(void *arg) {
    (void) arg;
    while (1) {
        int conn_fd = -1;
        queue_pop(queue, (void *) (uintptr_t *) &conn_fd);
        handleCon(conn_fd);
        close(conn_fd);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Bad number of arguments\n");
        exit(1);
    }

    int opt = 0;
    int threads = 4;
    while ((opt = getopt(argc, argv, "t:")) != -1) {
        if (opt == 't') {
            threads = atoi(optarg);
            if (threads <= 0) {
                fprintf(stderr, "Invalid number of threads\n");
                exit(1);
            }
        }
    }

    char *endptr;
    int port = strtol(argv[optind], &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid port\n");
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);

    Listener_Socket sock;
    if (listener_init(&sock, port) == -1) {
        fprintf(stderr, "Unable to initialize listener on port %d\n", port);
        exit(1);
    }

    sock_fd = sock.fd;
    queue = queue_new(threads);
    log_lock
        = rwlock_new(N_WAY, 10); // Replace PRIORITY_HIGH with N_WAY (or READERS/WRITERS as needed)

    pthread_t thread_arr[threads];
    for (int i = 0; i < threads; i++) {
        pthread_create(&thread_arr[i], NULL, worker, NULL);
    }

    while (1) {
        int conn_fd = listener_accept(&sock);
        queue_push(queue, (void *) (uintptr_t) conn_fd);
    }

    return 0;
}
