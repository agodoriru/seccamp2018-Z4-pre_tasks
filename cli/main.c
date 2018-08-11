#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>


void loop();

int main(){

	loop();
	return 0;
}


void loop(){

	char input[64];

	while(1){
		fprintf(stdout, "> ");
		fgets(input,64,stdin);

		fprintf(stdout, '%s\n', input);
	}
}
