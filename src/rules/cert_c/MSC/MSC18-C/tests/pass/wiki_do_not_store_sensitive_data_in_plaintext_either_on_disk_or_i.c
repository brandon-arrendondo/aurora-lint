/*
 * Rule: MSC18-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

int validate(char *username) {
  char *password;
  char *checksum;
  password = read_password();
  checksum = compute_checksum(password);
  erase(password);  /* Securely erase password */
  return !strcmp(checksum, get_stored_checksum(username));
}