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
  char *bytes = (char *)header;
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

  strncpy(header->name, file_name,
          100);  // Name of the file, null-terminated string
  snprintf(header->mode, 8, "%07o",
           stat_buf.st_mode & 07777);  // Permissions for file, 0-padded octal

  snprintf(header->uid, 8, "%07o",
           stat_buf.st_uid);  // Owner ID of the file, 0-padded octal
  struct passwd *pwd =
      getpwuid(stat_buf.st_uid);  // Look up name corresponding to owner ID
  if (pwd == NULL) {
    snprintf(err_msg, MAX_MSG_LEN, "Failed to look up owner name of file %s",
             file_name);
    perror(err_msg);
    return -1;
  }
  strncpy(header->uname, pwd->pw_name,
          32);  // Owner name of the file, null-terminated string

  snprintf(header->gid, 8, "%07o",
           stat_buf.st_gid);  // Group ID of the file, 0-padded octal
  struct group *grp =
      getgrgid(stat_buf.st_gid);  // Look up name corresponding to group ID
  if (grp == NULL) {
    snprintf(err_msg, MAX_MSG_LEN, "Failed to look up group name of file %s",
             file_name);
    perror(err_msg);
    return -1;
  }
  strncpy(header->gname, grp->gr_name,
          32);  // Group name of the file, null-terminated string

  snprintf(header->size, 12, "%011o",
           (unsigned)stat_buf.st_size);  // File size, 0-padded octal
  snprintf(header->mtime, 12, "%011o",
           (unsigned)stat_buf.st_mtime);  // Modification time, 0-padded octal
  header->typeflag = REGTYPE;  // File type, always regular file in this project
  strncpy(header->magic, MAGIC, 6);  // Special, standardized sequence of bytes
  memcpy(header->version, "00", 2);  // A bit weird, sidesteps null termination
  snprintf(header->devmajor, 8, "%07o",
           major(stat_buf.st_dev));  // Major device number, 0-padded octal
  snprintf(header->devminor, 8, "%07o",
           minor(stat_buf.st_dev));  // Minor device number, 0-padded octal

  compute_checksum(header);
  return 0;
}

/*
 * Removes 'nbytes' bytes from the file identified by 'file_name'
 * Returns 0 upon success, -1 upon error
 * Note: This function uses lower-level I/O syscalls (not stdio), which we'll
 * learn about later
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
      fwrite(buffer, 1, BLOCK_SIZE, archive);  // Always write 512 bytes
      memset(buffer, 0, BLOCK_SIZE);           // Clear buffer for next chunk
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

int append_files_to_archive(const char *archive_name,
                            const file_list_t *files) {
  /* append_files_to_archive has arguments archive_name which is the archive given and files which is just
    a list of files we want to append (add) to the given archive. Returns 0 which indicates successfully 
    appending the files to the archive and it returns -1 if an error occured. */

  char err_msg[MAX_MSG_LEN]; // A buffer err_msg is defined to store error messages.

  FILE *archive = fopen(archive_name, "rb+"); // This opens the archive in read+write mode.
  if (!archive) { // If invalid archive given, it prints an error message.
    snprintf(err_msg, MAX_MSG_LEN,
             "Error opening archive file %s for appending", archive_name); // Error message is printed.
    perror(err_msg);
    return -1; // Returns -1 which indicates failure. 
  }

  fseek(archive, -BLOCK_SIZE * NUM_TRAILING_BLOCKS, SEEK_END); // Moves the file pointer backward by BLOCK_SIZE * NUM_TRAILING_BLOCKS bytes from the end of the file.

  long new_size = ftell(archive); // ftell(archive) gets the current position

  if (truncate(archive_name, new_size) != 0) { // truncate() resizes the file to new_size, effectively removing the existing footer.
    perror("Failed to remove footer before appending"); // Prints error message
    fclose(archive); // Closes archive.
    return -1;
  }
  fseek(archive, new_size, SEEK_SET); // Moves the file pointer to new_size, so that new data can be appended after the last valid archive content.

  node_t *head_file = files->head;
  while (head_file != NULL) { // Iterates through the files to make sure everything is valid.
    struct stat st;
    if (stat(head_file->name, &st) != 0) { // stat() retrieves metadata (size, permissions, etc.) of the current file. If it fails the file is invalid.
      snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", head_file->name);
      perror(err_msg);
      fclose(archive); // Close file
      return -1;
    }

    tar_header file_header; // Declares a tar_header structure and initializes it to zero using memset().
    memset(&file_header, 0, sizeof(tar_header));

    if (fill_tar_header(&file_header, head_file->name) != 0) { // Calls fill_tar_header() to populate the tar header with file details (name, size, permissions, etc.). Returns -1 if fails. 
      fclose(archive);
      return -1;
    }

    compute_checksum(&file_header); // The function compute_checksum() calculates the checksum for the header.
    fwrite(&file_header, 1, BLOCK_SIZE, archive); // The function fwrite() writes the header (512 bytes, assuming BLOCK_SIZE = 512) to the archive.

    FILE *current_file = fopen(head_file->name, "rb"); // Reads file contents in BLOCK_SIZE (512-byte) chunks.
    if (!current_file) {
      snprintf(err_msg, MAX_MSG_LEN, "Failed to open file %s for reading", // Error Message.
               head_file->name);
      perror(err_msg);
      fclose(archive);
      return -1; // Returns -1 for failure.
    }

    char buffer[BLOCK_SIZE] = {0}; // Declares a character array of size BLOCK_SIZE
    size_t bytes_read; // bytes_read stores the actual number of bytes read.
    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, current_file)) > 0) { // The while loop continues until the file is fully read.
      fwrite(buffer, 1, BLOCK_SIZE, archive); // Writes exactly 512 bytes (1 block) from buffer into the archive file.
      memset(buffer, 0, BLOCK_SIZE);  // Clear buffer
    }
    fclose(current_file); // Closes file
    head_file = head_file->next;
  }

  char footer[BLOCK_SIZE] = {0}; // Write new footer (two zero blocks)
  fwrite(footer, 1, BLOCK_SIZE, archive); // 1
  fwrite(footer, 1, BLOCK_SIZE, archive); // 2

  fclose(archive); // Close
  return 0; // Returning a 0 indicates a passing code.
}

int update_files_in_archive(const char *archive_name,
                            const file_list_t *files) {
  char err_msg[MAX_MSG_LEN]; // Holds the error messsage.

  FILE *archive = fopen(archive_name, "rb+"); // Opens the existing archive file for reading and writing.
  if (!archive) { // If an invalid archive, prints the error and -1 which indicates invalid archive.
    snprintf(err_msg, MAX_MSG_LEN, "Error opening archive file %s for updating",
             archive_name);
    perror(err_msg);
    return -1;
  }

  node_t *head_file = files->head; 

  while (head_file != NULL) { // Iterates through each file in files to check if it already exists in the archive.
    int file_exists = 0;
    FILE *check_archive = fopen(archive_name, "rb"); // Opens the archive again in read mode ("rb") to scan for the file.
    if (!check_archive) { // If an error arises when opening archive, return error message.
      perror("Error opening archive for checking");
      fclose(archive);
      return -1;
    }

    tar_header header; // Reads one file header at a time from the archive. The loop continues until all headers are checked.
    while (fread(&header, 1, sizeof(tar_header), check_archive) ==
           sizeof(tar_header)) {
      if (strcmp(header.name, head_file->name) == 0) { // If this passes, the file exists.
        file_exists = 1;
        break;
      }
      unsigned long size; // Extracts the file size from the header.
      sscanf(header.size, "%lo", &size);
      fseek(check_archive, ((size + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE,
            SEEK_CUR);
    }
    fclose(check_archive); // Closes.

    if (!file_exists) { // If any file is missing from the archive, an error message is printed, and the function exits.
      fprintf(stderr,
              "Error: One or more of the specified files is not already "
              "present in archive\n");
      fflush(stderr);
      fclose(archive);
      return -1;
    }

    head_file = head_file->next;
  }

  fseek(archive, -BLOCK_SIZE * NUM_TRAILING_BLOCKS, SEEK_END); // Moves the file pointer backwards by BLOCK_SIZE * NUM_TRAILING_BLOCKS
  long new_size = ftell(archive); // Resizes the file to new_size
  if (truncate(archive_name, new_size) != 0) { // If truncate() fails, it prints an error and exits.
    perror("Failed to remove footer before updating");
    fclose(archive);
    return -1;
  }
  fseek(archive, new_size, SEEK_SET);

  head_file = files->head;   // Overwrite existing files in the archive
  while (head_file != NULL) { 
    struct stat st; // Uses stat() to check if the file exists on the system.
    if (stat(head_file->name, &st) != 0) { // If stat() fails, the function prints an error and exits.
      snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", head_file->name);
      perror(err_msg);
      fclose(archive);
      return -1;
    }

    tar_header file_header;     // Write updated header
    memset(&file_header, 0, sizeof(tar_header)); // Uses fill_tar_header() to populate the header with metadata (name, size, etc.).
    if (fill_tar_header(&file_header, head_file->name) != 0) {
      fclose(archive);
      return -1;
    }
    compute_checksum(&file_header);
    fwrite(&file_header, 1, BLOCK_SIZE, archive);

    FILE *current_file = fopen(head_file->name, "rb"); // Opens the new version of the file in read mode ("rb").
    if (!current_file) { // If it fails, an error message is printed and the function exits.
      snprintf(err_msg, MAX_MSG_LEN, "Failed to open file %s for reading",
               head_file->name);
      perror(err_msg);
      fclose(archive);
      return -1;
    }

    char buffer[BLOCK_SIZE] = {0};
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, current_file)) > 0) {
      fwrite(buffer, 1, BLOCK_SIZE, archive);
      memset(buffer, 0, BLOCK_SIZE);  // Clear buffer
    }
    fclose(current_file);
    head_file = head_file->next;
  }

  char footer[BLOCK_SIZE] = {0};  // Write new footer (two zero blocks)
  fwrite(footer, 1, BLOCK_SIZE, archive);
  fwrite(footer, 1, BLOCK_SIZE, archive);

  fclose(archive);
  return 0;
}

int get_archive_file_list(const char *archive_name, file_list_t *files) {
  // TODO: Not yet implemented
  FILE *archive = fopen(archive_name, "rb");
  if (!archive) {
    perror("Failed to open archive");
    return -1;
  }

  tar_header header;
  while (1) {
    // Read header
    size_t bytes_read = fread(&header, 1, sizeof(tar_header), archive);
    if (bytes_read != sizeof(tar_header)) {
      if (feof(archive)) {
        break;  // End of file
      }
      perror("Failed to read header");
      fclose(archive);
      return -1;
    }

    // Check if we've hit the end (two zero blocks)
    int is_zero_block = 1;
    for (size_t i = 0; i < sizeof(tar_header); i++) {
      if (((char *)&header)[i] != 0) {
        is_zero_block = 0;
        break;
      }
    }
    if (is_zero_block) {
      break;  // Found footer (zero block)
    }

    // Print filename
    printf("%s\n", header.name);

    // Calculate number of 512-byte blocks for file content
    unsigned long size;
    sscanf(header.size, "%lo", &size);
    size_t blocks =
        (size + BLOCK_SIZE - 1) / BLOCK_SIZE;  // Round up to nearest block

    // Skip over file content blocks
    if (fseek(archive, blocks * BLOCK_SIZE, SEEK_CUR) != 0) {
      perror("Failed to skip file content");
      fclose(archive);
      return -1;
    }
  }

  fclose(archive);
  return 0;
}

int extract_files_from_archive(const char *archive_name) {
  // Open the archive file
  FILE *archive = fopen(archive_name, "rb");
  if (archive == NULL) {  // Checking if the it's a valid archive to open
    perror("Error opening archive");
    return -1;  // Indicates an invalid archive
  }

  char buffer[BLOCK_SIZE];  // Temporary buffer to read data
  while (fread(buffer, 1, BLOCK_SIZE, archive) == BLOCK_SIZE) {
    tar_header *header = (tar_header *)buffer;  // Read header

    // If the name is empty, we've reached the end of the archive
    if (header->name[0] == '\0') {
      break;
    }

    // Get the file name and size
    char file_name[101];
    strncpy(file_name, header->name, 100);
    file_name[100] = '\0';  // Ensure null-termination

    size_t file_size =
        strtol(header->size, NULL, 8);  // Convert size from octal to decimal

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
      size_t bytes_to_read =
          (bytes_remaining > BLOCK_SIZE) ? BLOCK_SIZE : bytes_remaining;

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
