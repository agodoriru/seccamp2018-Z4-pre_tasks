#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

void loop();
int shell_exit(char **args);
int shell_launch(char **args);

char *command_list_str[]={
	"help",
	"exit"
}; 

int main(int argc, char **argv){
 	loop();
	return 0;
} 

void loop(){

 	char input[64];

 	while(1){
		fprintf(stdout, "> ");
		fgets(input,64,stdin);

		// fprintf(stdout, "get command : %s", input);	
		// parser
		char *command=command_activate();
		fprintf(stdout, "%sn", command);
		shell_launch(input);

 
	}
}

char *command_activate(char **args){
	int command_counter;

	if(args[0]==NULL){
		return 1;
	}

	for(int i=0;i<command_counter;i++){
		if(strcmp(args[0],command_list_str[i]==0)){
			//same command found
			return (*command_list_str[i])(args);


		}
	}
}


int shell_launch(char **args){
	pid_t pid;
	pid_t wpid;

	int status;

	pid=fork();

	printf("%d\n",pid );

	if(pid==0){
		if(execvp(args[0],args)==-1){
			perror("lsh");
		}
		exit(EXIT_FAILURE);

	}else if(pid<0){
		perror("lsh");
	}else{
		do {
			wpid=waitpid(pid,&status,WUNTRACED);
		} while(!WIFEXITED(status)&&!WIFSIGNALED(status));
	}

	return 1;


}

int shell_exit(char **args){
	return 0;
}