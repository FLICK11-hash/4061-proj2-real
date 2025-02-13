#include <stdio.h>
#include <string.h>

#include "file_list.h"
#include "minitar.h"

int main(int argc, char** argv) {
  /* The main function is given two argument argc which is the amount of 
  arguments and argv is argument vector that has a string representing 
  command-line arguments. 
   */
  if (argc < 4) { // This checks if the user has provided at least four arguments.
    // If less than four, it informs the user the correct format.
    // An example of good input, ./minitar -c -f my_archive.tar file1.txt file2.txt
    printf("Usage: %s -c|a|t|u|x -f ARCHIVE [FILE...]\n", argv[0]);
    return 0;
  }

  file_list_t files; // Declares a file_list_t variable (files).
  file_list_init(&files); // Initializes the file list using file_list_init(&files).

  char* operation = argv[1]; // Stores the command (-c -a -t -u -x)
  char* archive = argv[3]; // Stores the name of the archive.

  for (int i = 4; i < argc; i++) { // Iterates thrhough all the files, if any.
    if (file_list_add(&files, argv[i]) != 0) {  // If adding a files to &files fails,
      fprintf(stderr, "Error adding file: %s\n", argv[i]); // it'll state the failed file.
      file_list_clear(&files);  // Clear file(s).
      return 1; // Returns one to indicate an error.           
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
    // Invalid argument passed. Returns one to indicate failure running.
    fprintf(stderr, "Invalid operation: %s\n", operation);
    file_list_clear(&files); // Clear files. 
    return 1;
  }

  file_list_clear(&files); // Clear files. 
  return 0; // Returns 0 which indicates valid arguments.
}
