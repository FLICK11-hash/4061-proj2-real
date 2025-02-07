#include "minitar.h"

#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#define NUM_TRAILING_BLOCKS 2
#define MAX_MSG_LEN 128
#define BLOCK_SIZE 512

// Constants for tar compatibility information
#define MAGIC "ustar"

// Constants to represent different file types
// We'll only use regular files in this project
#define REGTYPE '0'
#define DIRTYPE '5'

/*
 * Helper function to compute the checksum of a tar header block
 * Performs a simple sum over all bytes in the header in accordance with POSIX
 * standard for tar file structure.
 */
void compute_checksum(tar_header *header) {
    // Have to initially set header's checksum to "all blanks"
    memset(header->chksum, ' ', 8);
    unsigned sum = 0;
    char *bytes = (char *) header;
    for (int i = 0; i < sizeof(tar_header); i++) {
        sum += bytes[i];
    }
    snprintf(header->chksum, 8, "%07o", sum);
}

/*
 * Populates a tar header block pointed to by 'header' with metadata about
 * the file identified by 'file_name'.
 * Returns 0 on success or -1 if an error occurs
 */
int fill_tar_header(tar_header *header, const char *file_name) {
    memset(header, 0, sizeof(tar_header));
    char err_msg[MAX_MSG_LEN];
    struct stat stat_buf;
    // stat is a system call to inspect file metadata
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    strncpy(header->name, file_name, 100);    // Name of the file, null-terminated string
    snprintf(header->mode, 8, "%07o",
             stat_buf.st_mode & 07777);    // Permissions for file, 0-padded octal

    snprintf(header->uid, 8, "%07o", stat_buf.st_uid);    // Owner ID of the file, 0-padded octal
    struct passwd *pwd = getpwuid(stat_buf.st_uid);       // Look up name corresponding to owner ID
    if (pwd == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up owner name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->uname, pwd->pw_name, 32);    // Owner name of the file, null-terminated string

    snprintf(header->gid, 8, "%07o", stat_buf.st_gid);    // Group ID of the file, 0-padded octal
    struct group *grp = getgrgid(stat_buf.st_gid);        // Look up name corresponding to group ID
    if (grp == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up group name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->gname, grp->gr_name, 32);    // Group name of the file, null-terminated string

    snprintf(header->size, 12, "%011o",
             (unsigned) stat_buf.st_size);    // File size, 0-padded octal
    snprintf(header->mtime, 12, "%011o",
             (unsigned) stat_buf.st_mtime);    // Modification time, 0-padded octal
    header->typeflag = REGTYPE;                // File type, always regular file in this project
    strncpy(header->magic, MAGIC, 6);          // Special, standardized sequence of bytes
    memcpy(header->version, "00", 2);          // A bit weird, sidesteps null termination
    snprintf(header->devmajor, 8, "%07o",
             major(stat_buf.st_dev));    // Major device number, 0-padded octal
    snprintf(header->devminor, 8, "%07o",
             minor(stat_buf.st_dev));    // Minor device number, 0-padded octal

    compute_checksum(header);
    return 0;
}

/*
 * Removes 'nbytes' bytes from the file identified by 'file_name'
 * Returns 0 upon success, -1 upon error
 * Note: This function uses lower-level I/O syscalls (not stdio), which we'll learn about later
 */
int remove_trailing_bytes(const char *file_name, size_t nbytes) {
    char err_msg[MAX_MSG_LEN];

    struct stat stat_buf;
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    off_t file_size = stat_buf.st_size;
    if (nbytes > file_size) {
        file_size = 0;
    } else {
        file_size -= nbytes;
    }

    if (truncate(file_name, file_size) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to truncate file %s", file_name);
        perror(err_msg);
        return -1;
    }
    return 0;
}

// Written by Sayyam Sawai(sawai006)
int create_archive(const char *archive_name, const file_list_t *files) {
    // TODO: Not yet implemented
    // int files_n = files->size;
    node_t *head_file = files->head;

    // printf("number of files: %d\n", files_n);
    // printf("file name: %s\n", head_file->name);

    FILE *archive = fopen(archive_name, "wb");

    // Create header, populate header, get 512 blocks from file
    // fill into .tar file, keep doing until end, fill footer
    // move to next file

    while (head_file != NULL) {
        tar_header *file_header = malloc(sizeof(tar_header));
        fill_tar_header(file_header, head_file->name);

        fwrite(file_header, sizeof(tar_header), 1, archive);
        // printf("name from header: %s", file_header->name);

        FILE *current_file = fopen(head_file->name, "rb");

        if (current_file == NULL) {
            // fprintf(stderr, "File not found: %s\n", head_file->name);
            free(file_header);
            return -1;
        }

        char buffer[BLOCK_SIZE] = {0};
        size_t bytes_read;
        while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, current_file)) > 0) {
            fwrite(buffer, 1, BLOCK_SIZE, archive);    // Always write 512 bytes
            memset(buffer, 0, BLOCK_SIZE);             // Clear buffer for next chunk
        }
        fclose(current_file);
        free(file_header);
        head_file = head_file->next;
    }

    char footer[BLOCK_SIZE] = {0};
    fwrite(footer, 1, BLOCK_SIZE, archive);
    fwrite(footer, 1, BLOCK_SIZE, archive);

    fclose(archive);

    return 0;
}

int append_files_to_archive(const char *archive_name, const file_list_t *files) {
    // TODO: Not yet implemented
    return 0;
}

int get_archive_file_list(const char *archive_name, file_list_t *files) {
    // TODO: Not yet implemented
    return 0;
}

int extract_files_from_archive(const char *archive_name) {
    // Open the archive file
    FILE *archive = fopen(archive_name, "rb");
    if (archive == NULL) {    // Checking if the it's a valid archive to open
        perror("Error opening archive");
        return -1;    // Indicates an invalid archive
    }

    char buffer[BLOCK_SIZE];    // Temporary buffer to read data
    while (fread(buffer, 1, BLOCK_SIZE, archive) == BLOCK_SIZE) {
        tar_header *header = (tar_header *) buffer;    // Read header

        // If the name is empty, we've reached the end of the archive
        if (header->name[0] == '\0') {
            break;
        }

        // Get the file name and size
        char file_name[101];
        strncpy(file_name, header->name, 100);
        file_name[100] = '\0';    // Ensure null-termination

        size_t file_size = strtol(header->size, NULL, 8);    // Convert size from octal to decimal

        // Open a file to write the extracted content
        FILE *output = fopen(file_name, "wb");
        if (output == NULL) {
            perror("Error creating output file");
            fclose(archive);
            return -1;
        }

        // Write the file content from the archive
        size_t bytes_remaining = file_size;
        while (bytes_remaining > 0) {
            size_t bytes_to_read = (bytes_remaining > BLOCK_SIZE) ? BLOCK_SIZE : bytes_remaining;

            if (fread(buffer, 1, BLOCK_SIZE, archive) != BLOCK_SIZE) {
                fprintf(stderr, "Error reading file content for %s\n", file_name);
                fclose(output);
                fclose(archive);
                return -1;
            }

            fwrite(buffer, 1, bytes_to_read, output);
            bytes_remaining -= bytes_to_read;
        }

        fclose(output);

        // Skip padding if the file size isn't a multiple of 512 bytes
        if (file_size % BLOCK_SIZE != 0) {
            fseek(archive, BLOCK_SIZE - (file_size % BLOCK_SIZE), SEEK_CUR);
        }
    }

    fclose(archive);
    return 0;
}
