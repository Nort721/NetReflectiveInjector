#include <Windows.h>
#include <stdio.h>

int main() {
	while (1) {
		printf("process id: %d\n", GetCurrentProcessId());
		Sleep(2000);
	}
	return 1;
}
