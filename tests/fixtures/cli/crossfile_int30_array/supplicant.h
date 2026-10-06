#include <stddef.h>

struct supplicant {
#ifdef CONFIG_SME
	struct {
		unsigned char assoc_req_ie[1500];
		size_t assoc_req_ie_len;
	} sme;
#endif
};
