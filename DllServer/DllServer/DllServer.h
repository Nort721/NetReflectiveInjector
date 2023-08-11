#define INDEX_TARGET_PROCESS_ID 1
#define ERROR_WITH_CODE(e) (printf("[-] ERROR: %s, 0x%x\r\n", e, GetLastError()))
#define ERROR(e) (printf("[-] ERROR: %s\r\n", e))
#define INFO_WITH_CODE(e) (printf("[*] INFO: %s, 0x%x\r\n", e, GetLastError()))
#define INFO(e) (printf("[*] INFO: %s\r\n", e))
#define SUCCESS(e) (printf("[+] SUCCESS: %s\r\n", e))