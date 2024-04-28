gcc -o logfile_threads logfile_threads.c -lpthread -fsanitize=address
gcc -o baucotest baucotest.c -lpthread -fsanitize=address
gcc -o listhead_threads listhead_threads.c -lpthread -fsanitize=address