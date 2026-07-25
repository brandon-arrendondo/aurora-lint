/*
 * Rule: MEM01-C
 * Source: testcases (task 320 follow-up)
 * Status: PASS - Should NOT trigger MEM01-C violation
 * Description: `value` is freed in one switch-case arm and freed again in a
 * different, mutually-exclusive arm reached on a later loop iteration -- but
 * each arm reassigns `value` via an output parameter (`read_pair(..., &value,
 * ...)`) before touching it again, including when that call sits inside an
 * if-condition. Modeled on mosquitto's mosquitto_properties_to_json()
 * (libcommon/cjson_common.c), which false-positived once switch/case bodies
 * became visible to the CFG (task 320).
 */

#include <stdlib.h>
#include <stdbool.h>

typedef struct property property;

int read_string(property *p, int id, char **out, bool b);
int read_pair(property *p, int id, char **name, char **out, bool b);
property *next_property(property *p);
int property_id(property *p);
int add_string(void *obj, const char *key, char *val);

void emit_properties(property *properties) {
    char *name, *value;
    int propid;

    do {
        propid = property_id(properties);

        switch (propid) {
        case 1:
            if (read_string(properties, propid, &value, false) == NULL) {
                return;
            }
            if (add_string(NULL, "value", value) == NULL) {
                free(value);
                return;
            }
            free(value);
            break;
        case 2:
            read_pair(properties, propid, &name, &value, false);
            if (add_string(NULL, "name", name) == NULL || add_string(NULL, "value", value) == NULL) {
                free(name);
                free(value);
                return;
            }
            free(name);
            free(value);
            break;
        default:
            break;
        }

        properties = next_property(properties);
    } while (properties);
}
