#include <linux/types.h>

// I didn't find where this structure is located, seems interal.h but doesn't work, so i decided to import manually.
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};