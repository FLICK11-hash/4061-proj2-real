#include <stdio.h>
#include <string.h>

#include "file_list.h"
#include "minitar.h"

int main(int argc, char** argv) {
  if (argc < 4) {
    printf("Usage: %s -c|a|t|u|x -f ARCHIVE [FILE...]\n", argv[0]);
    return 0;
  }

  file_list_t files;
  file_list_init(&files);

  // Parse command-line arguments and invoke functions from 'minitar.h'
  char* operation = argv[1];
  char* archive = argv[3];

  for (int i = 4; i < argc; i++) {
    // Check for a valid archive command.
    if (file_list_add(&files, argv[i]) != 0) {
      fprintf(stderr, "Error adding file: %s\n", argv[i]);
      file_list_clear(&files);  // Clears invalid file(s).
      return 1;                 // Returns 1, indicating an error.
    }
  }

  if (strcmp(operation, "-c") == 0) {
    // Creates archive.
    create_archive(archive, &files);
  } else if (strcmp(operation, "-t") == 0) {
    // Lists files in archive.
    get_archive_file_list(archive, &files);
  } else if (strcmp(operation, "-a") == 0) {
    // Appends new files to an archive.
    append_files_to_archive(archive, &files);
  } else if (strcmp(operation, "-u") == 0) {
    // Updates existing files in an archive.
    update_files_in_archive(archive, &files);
  } else {
    fprintf(stderr, "Invalid operation: %s\n", operation);
    file_list_clear(&files);
    return 1;
  }

  file_list_clear(&files);
  return 0;
}
